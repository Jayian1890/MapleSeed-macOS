#include "decrypt.h"
#include "configuration.h"

Decrypt* Decrypt::self;

Decrypt::Decrypt(QObject* parent) : QObject(parent) {
	Decrypt::self = this;
}

void Decrypt::start(QString basedir) {
	auto tmd = QString(basedir + "\\tmd");
	auto cetk = QString(basedir + "\\cetk");
	this->doDecrypt(tmd, cetk, basedir);
    qInfo() << "Decrypt Complete" << basedir;
}

quint32 Decrypt::bs24(quint32 i) {
	return ((i & 0xFF0000) >> 16) | ((i & 0xFF) << 16) | (i & 0x00FF00);
}

qulonglong Decrypt::bs64(qulonglong i) {
	return static_cast<qulonglong>(((static_cast<qulonglong>(bs32(i & 0xFFFFFFFF))) << 32) | (bs32(i >> 32)));
}

char* Decrypt::_ReadFile(QString file, quint32 * len) {
	QFile in(file);
	if (!in.open(QIODevice::ReadOnly)) {
		return nullptr;
	}

	*len = static_cast<quint32>(in.size());
	QByteArray bytearray(in.readAll());
	in.close();

	size_t size = static_cast<size_t>(bytearray.size());
	char* data = new char[size];
	memcpy(data, bytearray.data(), size);
	return data;
}

void Decrypt::FileDump(QString file, void* data, quint32 len) {
	if (data == nullptr) {
        qWarning() << "invalid dump data";
		return;
	}
	if (len == 0) {
        qWarning() << "invalid dump size";
		return;
	}

	QFile out(file);
	if (!out.open(QIODevice::WriteOnly)) {
        qCritical() << out.errorString();
		return;
	}
	
	if (out.isWritable()) {
        out.write(QByteArray(reinterpret_cast<const char*>(data), static_cast<qint32>(len)));
	}

	out.close();
}

char Decrypt::ascii(char s) {
	if (s < 0x20)
		return '.';
	if (s > 0x7E)
		return '.';
	return s;
}

void Decrypt::hexdump(void* d, qint32 len) {
	quint8* data;
	qint32 i, off;
	data = static_cast<quint8*>(d);
	for (off = 0; off < len; off += 16) {
		printf("%08x  ", off);
		for (i = 0; i < 16; i++)
			if ((i + off) >= len)
				printf("   ");
			else
				printf("%02x ", data[off + i]);

		printf(" ");
		for (i = 0; i < 16; i++)
			if ((i + off) >= len)
				printf(" ");
			else
				printf("%c", ascii(static_cast<char>(data[off + i])));
		printf("\n");
	}
}

#define BLOCK_SIZE  0x10000
void Decrypt::ExtractFileHash(QFile * in, qulonglong PartDataOffset, qulonglong FileOffset, qulonglong Size, QString FileName, quint16 ContentID, int i1, int i2) {
	char encdata[BLOCK_SIZE];
	char decdata[BLOCK_SIZE];
	quint8 IV[16];
	quint8 hash[SHA_DIGEST_LENGTH];
	quint8 H0[SHA_DIGEST_LENGTH];
	quint8 Hashes[0x400];

	qulonglong Wrote = 0;
	qulonglong totsz = Size;
	qulonglong WriteSize = 0xFC00;  // Hash block size
	qulonglong Block = (FileOffset / 0xFC00) & 0xF;

	QFile* out = new QFile(FileName);
	if (!out->open(QIODevice::WriteOnly)) {
        qCritical() << out->errorString();
		exit(0);
	}

	qulonglong roffset = FileOffset / 0xFC00 * BLOCK_SIZE;
	qulonglong soffset = FileOffset - (FileOffset / 0xFC00 * 0xFC00);

	if (soffset + Size > WriteSize)
		WriteSize = WriteSize - soffset;

	in->seek(static_cast<qlonglong>(PartDataOffset + roffset));
	while (Size > 0) {
		if (WriteSize > Size)
			WriteSize = Size;

		in->read(encdata, BLOCK_SIZE);

		memset(IV, 0, sizeof(IV));
		IV[1] = static_cast<quint8>(ContentID);
		AES_cbc_encrypt(reinterpret_cast<const quint8*>(encdata), static_cast<quint8*>(Hashes), 0x400, &_key, IV, AES_DECRYPT);

		memcpy(H0, Hashes + 0x14 * Block, SHA_DIGEST_LENGTH);

		memcpy(IV, Hashes + 0x14 * Block, sizeof(IV));
		if (Block == 0)
			IV[1] ^= ContentID;
		AES_cbc_encrypt(reinterpret_cast<const quint8*>(encdata + 0x400), reinterpret_cast<quint8*>(decdata), 0xFC00, &_key, IV, AES_DECRYPT);

		SHA1(reinterpret_cast<const quint8*>(decdata), 0xFC00, hash);
		if (Block == 0)
			hash[1] ^= ContentID;
		H0Count++;
		if (memcmp(hash, H0, SHA_DIGEST_LENGTH) != 0) {
			H0Fail++;
			hexdump(hash, SHA_DIGEST_LENGTH);
			hexdump(Hashes, 0x100);
            hexdump(decdata, 0x100);
            qCritical() << "failed to verify H0 hash:" << out->fileName();
			return;
		}

        Size -= out->write(decdata + soffset, WriteSize);

		Wrote += WriteSize;

		Block++;
		if (Block >= 16)
			Block = 0;

		if (soffset) {
			WriteSize = 0xFC00;
			soffset = 0;
		}
		emit progressReport2(Wrote, totsz, i1, i2);
	}

	out->close();
	delete out;
}
#undef BLOCK_SIZE

#define BLOCK_SIZE  0x8000
void Decrypt::ExtractFile(QFile * in, qulonglong PartDataOffset, qulonglong FileOffset, qulonglong Size, QString FileName, quint16 ContentID, int i1, int i2) {
	char encdata[BLOCK_SIZE];
	char decdata[BLOCK_SIZE];
	qulonglong Wrote = 0;
	qulonglong totsz = Size;

	//calc real offset
	qulonglong roffset = FileOffset / BLOCK_SIZE * BLOCK_SIZE;
	qulonglong soffset = FileOffset - (FileOffset / BLOCK_SIZE * BLOCK_SIZE);
	//printf("Extracting:\"%s\" RealOffset:%08llX RealOffset:%08llX\n", FileName, roffset, soffset );

	QFile* out = new QFile(FileName);
	if (!out->open(QIODevice::WriteOnly)) {
        qCritical() << out->errorString();
		exit(0);
	}
	quint8 IV[16];
	memset(IV, 0, sizeof(IV));
	IV[1] = static_cast<quint8>(ContentID);
	qulonglong WriteSize = BLOCK_SIZE;

	if (soffset + Size > WriteSize)
		WriteSize = WriteSize - soffset;

	in->seek(static_cast<qlonglong>(PartDataOffset + roffset));

	while (Size > 0) {
		if (WriteSize > Size)
			WriteSize = Size;

		in->read(encdata, BLOCK_SIZE);

		AES_cbc_encrypt(reinterpret_cast<const quint8*>(encdata), reinterpret_cast<quint8*>(decdata), BLOCK_SIZE, &_key, IV, AES_DECRYPT);
		Size -= out->write(decdata + soffset, WriteSize);
		Wrote += WriteSize;

		if (soffset) {
			WriteSize = BLOCK_SIZE;
			soffset = 0;
		}
		emit progressReport2(Wrote, totsz, i1, i2);
	}

	out->close();
	delete out;
}

qint32 Decrypt::doDecrypt(QString qtmd, QString qcetk, QString basedir)
{
    qInfo() << "Original CDecrypt v2.0b written by crediar";

	quint32 TMDLen;
	char* TMD = _ReadFile(qtmd, &TMDLen);
	if (TMD == nullptr) {
        qCritical() << "failed to open tmd" << qtmd;
		return EXIT_FAILURE;
	}

	quint32 TIKLen;
	char* TIK = _ReadFile(qcetk, &TIKLen);
	if (TIK == nullptr) {
        qCritical() << "failed to open cetk" << qcetk;
		return EXIT_FAILURE;
	}

	TitleMetaData* tmd = reinterpret_cast<TitleMetaData*>(TMD);

	if (tmd->Version != 1) {
        qCritical() << QString("Unsupported TMD Version:%1").arg(tmd->Version);
		return EXIT_FAILURE;
	}

    qInfo() << QString("Title version:%1").arg(bs16(tmd->TitleVersion));
    qInfo() << QString("Content Count:%1").arg(bs16(tmd->ContentCount));

	if (strcmp(TMD + 0x140, "Root-CA00000003-CP0000000b") == 0) {
		AES_set_decrypt_key(reinterpret_cast<const quint8*>(WiiUCommenKey), sizeof(WiiUCommenKey) * 8, &_key);
	}
	else if (strcmp(TMD + 0x140, "Root-CA00000004-CP00000010") == 0) {
		AES_set_decrypt_key(reinterpret_cast<const quint8*>(WiiUCommenDevKey), sizeof(WiiUCommenDevKey) * 8, &_key);
	}
	else {
		printf("Unknown Root type:\"%s\"\n", TMD + 0x140);
		return EXIT_FAILURE;
	}

	memset(title_id, 0, sizeof(title_id));
	memcpy(title_id, TMD + 0x18C, 8);
	memcpy(enc_title_key, TIK + 0x1BF, 16);

	AES_cbc_encrypt(enc_title_key, dec_title_key, sizeof(dec_title_key), &_key, title_id, AES_DECRYPT);
	AES_set_decrypt_key(dec_title_key, sizeof(dec_title_key) * 8, &_key);

	char iv[16];
	memset(iv, 0, sizeof(iv));

	QString _str;
	_str = basedir + QString().sprintf("/%08x.app", bs32(tmd->Contents[0].ID));

	quint32 CNTLen;
	char* CNT = _ReadFile(_str, &CNTLen);
	if (CNT == static_cast<char*>(nullptr)) {
		_str = basedir + QString().sprintf("/%08x", bs32(tmd->Contents[0].ID));
		CNT = _ReadFile(_str, &CNTLen);
		if (CNT == static_cast<char*>(nullptr)) {
            qInfo() << QString("Failed to open content:%1").arg(bs32(tmd->Contents[0].ID));
			return EXIT_FAILURE;
		}
	}

	if (bs64(tmd->Contents[0].Size) != static_cast<qulonglong>(CNTLen)) {
        qInfo() << QString("Size of content:%1 is wrong: %2:%3").arg(bs32(tmd->Contents[0].ID)).arg(CNTLen).arg(bs64(tmd->Contents[0].Size));
		return EXIT_FAILURE;
	}

	AES_cbc_encrypt(reinterpret_cast<const quint8*>(CNT), reinterpret_cast<quint8*>(CNT), CNTLen, &_key, reinterpret_cast<quint8*>(iv), AES_DECRYPT);

	if (bs32(*reinterpret_cast<quint32*>(CNT)) != 0x46535400) {
		_str = basedir + QString().sprintf("/%08x.dec", bs32(tmd->Contents[0].ID));
		FileDump(_str, CNT, CNTLen);
		return EXIT_FAILURE;
	}

	FST* _fst = reinterpret_cast<FST*>(CNT);

    qInfo() << QString("FSTInfo Entries:%1").arg(bs32(_fst->EntryCount));
	if (bs32(_fst->EntryCount) > 90000) {
		return EXIT_FAILURE;
	}

	FEntry* fe = reinterpret_cast<FEntry*>(CNT + 0x20 + bs32(_fst->EntryCount) * 0x20);

	quint32 Entries = bs32(*reinterpret_cast<quint32*>(CNT + 0x20 + bs32(_fst->EntryCount) * 0x20 + 8));
	quint32 NameOff = 0x20 + bs32(_fst->EntryCount) * 0x20 + Entries * 0x10;

    qInfo() << QString("FST entries:%1").arg(Entries);

	char* Path = new char[1024];
	QDir dir(basedir);
	qint32 Entry[16];
	qint32 LEntry[16];

	qint32 level = 0;

	emit decryptStarted();
	for (quint32 i = 1; i < Entries; ++i) {
		if (level) {
			while (static_cast<quint32>(LEntry[level - 1]) == i) {
				//printf("[%03X]leaving :\"%s\" Level:%d\n", i, CNT + NameOff + bs24( fe[Entry[level-1]].NameOffset ), level );
				level--;
			}
		}

		if (fe[i].u1.s1.Type & 1) {
			Entry[level] = static_cast<qint32>(i);
			LEntry[level++] = static_cast<qint32>(bs32(fe[i].u2.s3.NextOffset));
			if (level > 15) { // something is wrong!
                qCritical() << QString("level error:%1").arg(level);
				break;
			}
		}
		else {
			memset(Path, 0, 1024);

			for (qint32 j = 0; j < level; ++j) {
				if (j) {
					Path[strlen(Path)] = '\\';
                }
				memcpy(Path + strlen(Path), CNT + NameOff + bs24(fe[Entry[j]].u1.s1.NameOffset), strlen(CNT + NameOff + bs24(fe[Entry[j]].u1.s1.NameOffset)));
				QDir().mkdir(dir.filePath(Path));
			}
			if (level) {
				Path[strlen(Path)] = '\\';
			}
			memcpy(Path + strlen(Path), CNT + NameOff + bs24(fe[i].u1.s1.NameOffset), strlen(CNT + NameOff + bs24(fe[i].u1.s1.NameOffset)));

			quint32 CNTSize = bs32(fe[i].u2.s2.FileLength);
			qulonglong CNTOff = (static_cast<qulonglong>(bs32(fe[i].u2.s2.FileOffset)));

			if ((bs16(fe[i].Flags) & 4) == 0) {
				CNTOff <<= 5;
			}

            auto msg(QString().sprintf("Size:%1 Offset:0x%2 CID:%3 U:%4 %5", CNTSize, CNTOff, bs16(fe[i].ContentID), bs16(fe[i].Flags), Path));
            qInfo() << msg.arg(CNTSize).arg(CNTOff).arg(bs16(fe[i].ContentID)).arg(bs16(fe[i].Flags)).arg(Path);

			quint32 ContFileID = bs32(tmd->Contents[bs16(fe[i].ContentID)].ID);

			auto fei = fe[i];
			if (!(fei.u1.s1.Type & 0x80)) {
				QString filepath = basedir + QString().sprintf("/%08x", ContFileID);
				QFile* in = new QFile(filepath);
				if (!in->open(QIODevice::ReadOnly)) {
                    qWarning() << QString("Could not open:\"%1\"").arg(filepath);
					continue;
				}
				QString output(dir.filePath(Path));
				QFile outputFile(output);
				if ((bs16(fei.Flags) & 0x440)) {
					if (!outputFile.exists() || outputFile.size() != bs32(fei.u2.s2.FileLength))
						ExtractFileHash(in, 0, CNTOff, bs32(fei.u2.s2.FileLength), output, bs16(fei.ContentID), i, Entries - 1);
				}
				else {
					if (!outputFile.exists() || outputFile.size() != bs32(fei.u2.s2.FileLength))
						ExtractFile(in, 0, CNTOff, bs32(fei.u2.s2.FileLength), output, bs16(fei.ContentID), i, Entries - 1);
				}
				in->close();
				delete in;
			}
		}
	}
	emit progressReport(0, 100);
	emit decryptFinished();
	return EXIT_SUCCESS;
}
