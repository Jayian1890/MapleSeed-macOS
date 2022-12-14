#ifndef DECRYPT_H
#define DECRYPT_H

#include <QObject>
#include <QMessageBox>
#include <QtConcurrent>
#include <QDir>
#include <QFile>
#include <openssl\aes.h>
#include <openssl\sha.h>

class Decrypt : public QObject {
#pragma pack(push, 1)

#define bs16(s) static_cast<quint16>( ((s)>>8) | ((s)<<8) )
	//#define bs32(s) (quint32)( (((s)&0xFF0000)>>8) | (((s)&0xFF00)<<8) | ((s)>>24) | ((s)<<24) )
#define bs32(s) static_cast<quint32>( (((s)&0xFF0000)>>8) | (((s)&0xFF00)<<8) | ((s)>>24) | ((s)<<24) )

	Q_OBJECT

public:
	explicit Decrypt(QObject * parent = nullptr);

    void start(QString basedir);
    static void run(QString baseDir) { return self->start(baseDir); }
	static quint32 bs24(quint32 i);
	static qulonglong bs64(qulonglong i);

	static Decrypt * self;

signals:
	void decryptStarted();
	void decryptFinished();
	void progressReport(quint32 min, quint32 max);
    void progressReport2(qint64 min, qint64 max, int curfile, int maxfile);

private:
	AES_KEY _key;
	quint8 enc_title_key[16];
	quint8 dec_title_key[16];
	quint8 title_id[16];

	qulonglong H0Count = 0;
	qulonglong H0Fail = 0;

	char* _ReadFile(QString file, quint32* len);
	void FileDump(QString file, void* data, quint32 len);
	char ascii(char s);
	void hexdump(void* d, qint32 len);
	void ExtractFileHash(QFile* in, qulonglong PartDataOffset, qulonglong FileOffset, qulonglong Size, QString FileName, quint16 ContentID, int i1, int i2);
	void ExtractFile(QFile* in, qulonglong PartDataOffset, qulonglong FileOffset, qulonglong Size, QString FileName, quint16 ContentID, int i1, int i2);
	qint32 doDecrypt(QString qtmd, QString qcetk, QString basedir);

	unsigned char WiiUCommenDevKey[16] = { 0x2F, 0x5C, 0x1B, 0x29, 0x44, 0xE7, 0xFD, 0x6F, 0xC3, 0x97, 0x96, 0x4B, 0x05, 0x76, 0x91, 0xFA };
	unsigned char WiiUCommenKey[16] = { 0xD7, 0xB0, 0x04, 0x02, 0x65, 0x9B, 0xA2, 0xAB, 0xD2, 0xCB, 0x0D, 0xB2, 0x7F, 0xA2, 0xB6, 0x56 };

public:
	enum ContentType {
		CONTENT_REQUIRED = (1 << 0),            // not sure
		CONTENT_SHARED = (1 << 15),
		CONTENT_OPTIONAL = (1 << 14),
	};

	typedef struct {
		quint16 IndexOffset;    //      0        0x204
		quint16 CommandCount;   //      2        0x206
		quint8  SHA2[32];                       //  12 0x208
	} ContentInfo;

	typedef struct {
		quint32 ID;                                     //      0        0xB04
		quint16 Index;                  //      4  0xB08
		quint16 Type;                           //      6        0xB0A
		qulonglong Size;                                //      8        0xB0C
		quint8  SHA2[32];               //  16 0xB14
	} Content;

	typedef struct {
		quint32 SignatureType;          // 0x000
		quint8  Signature[0x100];       // 0x004

		quint8  Padding0[0x3C];         // 0x104
		quint8  Issuer[0x40];                   // 0x140

		quint8  Version;                                        // 0x180
		quint8  CACRLVersion;                   // 0x181
		quint8  SignerCRLVersion;       // 0x182
		quint8  Padding1;                                       // 0x183

		qulonglong      SystemVersion;          // 0x184
		qulonglong      TitleID;                                        // 0x18C
		quint32 TitleType;                              // 0x194
		quint16 GroupID;                                        // 0x198
		quint8  Reserved[62];                   // 0x19A
		quint32 AccessRights;                   // 0x1D8
		quint16 TitleVersion;                   // 0x1DC
		quint16 ContentCount;                   // 0x1DE
		quint16 BootIndex;                              // 0x1E0
		quint8  Padding3[2];                    // 0x1E2
		quint8  SHA2[32];                                       // 0x1E4

		ContentInfo ContentInfos[64];

		Content Contents[1024];         // 0x1E4

	} TitleMetaData;

	struct FSTInfo {
		quint32 Unknown;
		quint32 Size;
		quint32 UnknownB;
		quint32 UnknownC[6];
	};
	struct FST {
		quint32 MagicBytes;
		quint32 Unknown;
		quint32 EntryCount;

		quint32 UnknownB[5];

		FSTInfo FSTInfos[1024];
	};

	struct FEntry {
		union u1 {
			struct s1 {
				quint32 Type : 8;
				quint32 NameOffset : 24;
			};
			quint32 TypeName;
			s1 s1;
		};
		u1 u1;
		union u2 {
			struct s2 {         // File Entry
				quint32 FileOffset;
				quint32 FileLength;
			};
			s2 s2;
			struct s3 {         // Dir Entry
				quint32 ParentOffset;
				quint32 NextOffset;
			};
			s3 s3;
			quint32 entry[2];
		};
		u2 u2;
		unsigned short Flags;
		unsigned short ContentID;
    };

#pragma pack(pop)
};

#endif // DECRYPT_H
