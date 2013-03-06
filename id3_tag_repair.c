/*
  説明：
    ID3タグAPICフレーム内のMIMEタイプ修正ツール
    optionで同タイプのAPICフレームを2番目以降削除可能
	optionで指定フレームの全削除が可能
	・拡張ヘッダのCRC32には未対応
	・フレームの圧縮や暗号化には未対応
  
  参考 :
     http://www.takaaki.info/id3/ID3v2.3.0J.html

  最終更新日：2011年06月12日
  作成日　　：2011年06月03日
  作成者　　：gbm
*/


/****************************************************/
/*                     include                      */
/****************************************************/
#include <stdio.h>
#include <stdlib.h> // exit
#include <string.h> // strlen
#include <getopt.h> // getopt_long



/****************************************************/
/*                      define                      */
/****************************************************/
//#define DEBUG_ON
//#define DEBUG2_ON

#define RET_OK 0
#define RET_ERROR -1
#define RET_FAILURE 1
#define RET_REPETITION 1

#define FOUR_BYTE 0x04

#define STR_BUF 8
#define READ_BUF_SIZE 256
#define MIMETYPE_MAXSIZE 64

#define ID3_HEADER_SIZE 10
#define ID3_HEADER_ID_CHECK "ID3"
#define ID3_HEADER_VERSION_CHECK 0x03
#define ID3_HEADER_ID_SIZE 3
#define ID3_FRAME_ID_PIC "APIC"
#define ID3_FRAME_ID_SIZE 4
#define ID3_FRAME_SIZE 10

#define LONGOPT_REPETITION 0    // long opt num
#define OPTFLAG_REPETITION 0x01 // optflag

#define LONGOPT_DELETE 1        // long opt num
#define OPTFLAG_DELETE 0x02     // optflag

#define LONGOPT_VERBOSE 2       // long opt num
#define OPTFLAG_VERBOSE 0x04    // optflag

#define APICTYPE_NUM 0x15

#define REVERSE_ENDIAN(n)				\
	(									\
		  ((n & 0xFF000000) >> 24)		\
		| ((n & 0x00FF0000) >> 8)		\
		| ((n & 0x0000FF00) << 8)		\
		| ((n & 0x000000FF) << 24)		\
	)

// SYNCHSAFE変換系はv2.3タグでは利用しない(v2.4only)
// v2.3でもヘッダサイズのみ同じ形式で保存される
// ENDIANも変換する
#define FROM_SYNCHSAFE(n)			\
	(								\
     	  ((n & 0x7F000000) >> 24)	\
     	+ ((n & 0x007F0000) >> 9)	\
     	+ ((n & 0x00007F00) << 6)	\
		+ ((n & 0x0000007F) << 21)	\
	)

#define TO_SYNCHSAFE(n)				\
	(								\
     	  ((n & 0x0FE00000) >> 21)	\
     	+ ((n & 0x001FC000) >> 6)	\
     	+ ((n & 0x00003F80) << 9)	\
		+ ((n & 0x0000007F) << 24)	\
	)



/****************************************************/
/*                      struct                      */
/****************************************************/

/* ID3header *************************
   
     ID3v2/ファイル識別子      "ID3"
     ID3v2 バージョン          $03 00
     ID3v2 フラグ              %abcd0000
     ID3v2 サイズ          4 * %0xxxxxxx

  *ID3v2タグサイズは拡張ヘッダ、Padding領域、全てのフレームのバイト長を格
   納している。フッタが存在している場合、この値は('全長' - 20)バイト、そ
   うでなければ('全長' - 10)バイトに等しい。

**************************************/
typedef struct id3header{
	char id3[ID3_HEADER_ID_SIZE];
	unsigned char version[2];
	unsigned char flag;
	unsigned int size;
}ID3HEADER;

#define FLAG_SYN 0x80
#define FLAG_EXT 0x40
#define FLAG_EXP 0x20
//#define FLAG_FTR 0x10 v2.4から


/* ID3extheader **************************
   拡張ヘッダサイズ $xx xx xx xx
   拡張フラグ $xx xx
   Padding領域のサイズ $xx xx xx xx
******************************************/
typedef struct id3extheader{
	unsigned int size;
	unsigned char flag[2];
	unsigned int padding_size;
	unsigned char crc[4];
} ID3EXTHEADER;

#define EXT_FLAG_CRC 0x80


/* ID3frameheader **************************
     フレーム ID      $xx xx xx xx  (４文字)
     サイズ       4 * %0xxxxxxx
     フラグ           $xx xx
******************************************/
typedef struct id3frameheader{
	char id[ID3_FRAME_ID_SIZE];
	unsigned int size;
	unsigned char flag[2];
}ID3FRAMEHEADER;


/* ID3APICframe **************************
   Text encoding $xx
   MIME type <text string> $00
   Picture type $xx
   Description <text string according to encoding> $00 (00)
   Picture data <binary data>
******************************************/
typedef struct id3apicframe{
	unsigned char encode;
	char mimetype[MIMETYPE_MAXSIZE];
	unsigned char pictype;
	unsigned char description;
	unsigned char *data;
	
}ID3APICFRAME;

#define PICTURE_TYPE_NUM 0x15



/****************************************************/
/*                   prototype                      */
/****************************************************/
int fpstr(FILE *fp, const char *str, fpos_t npos);
int fcopy(FILE *fpw, FILE *fpr);
int fncopy(FILE *fpw, FILE *fpr, size_t n);

int read_id3_header(ID3HEADER *header, FILE *fp);
int read_id3_extheader(ID3EXTHEADER *header, FILE *fp);
int read_id3_frame_header(ID3FRAMEHEADER *header, FILE *fp);

int write_id3_header(const ID3HEADER *header, FILE *fp);
int write_id3_extheader(const ID3EXTHEADER *header, FILE *fp);
int write_id3_frame(const ID3FRAMEHEADER *header, FILE *fpr, FILE *fpw);
int write_id3_repair_apic_frame(const ID3FRAMEHEADER *header, FILE *fpr, FILE *fpw);

int seek_id3_next_frame(FILE *fp, const ID3FRAMEHEADER *header);
int get_id3_apic_type(FILE *fp, unsigned char *apictype);

int check_id3_mime_type(FILE *fp);
unsigned int get_id3_repair_size(FILE *fp);
int repair_id3_tag(FILE *fpw, FILE *fpr, unsigned int headersize);



/****************************************************/
/*                     Global                       */
/****************************************************/
static unsigned char g_flag = 0;
static char g_del_frametype[ID3_FRAME_ID_SIZE+1];
static char g_filename[FILENAME_MAX];



/****************************************************/
/*                    Process                       */
/****************************************************/

// Usage
void usage(const char *this) {
	fprintf(stderr, "Usage: %s [option] filename\n", this);
	fprintf(stderr, "  -r, --repetition : When APIC frame comes out two times or more, it is deleted.\n");
	fprintf(stderr, "  -d FRAMETYPE, --delete FRAMETYPE : All frames of a specified type are deleted.\n");
	fprintf(stderr, "  -v, --verbose : Verbose mode.\n");
	exit(EXIT_FAILURE);
}


/* main *************************************************************
    ID3 v2.3でのみ使用可能
    最低限の機能しか実装しないため多くを期待してはならない

  機能：
    1.APICフレームのMIME指定でima ge/jpegとなっている物をimage/jpegと修正する
	2.同一タイプのAPICフレームがあった場合2つ目以降を削除する(opt [-r])
	3.指定されたタイプのフレームを削除する(opt [-d FRAMETYPE])
    1～3実行後それに伴ったヘッダサイズ等のサイズ変更も行う
********************************************************************/
int main(int argc, char *argv[]) {
	FILE *fpr = NULL;
	FILE *fpw = NULL;
	unsigned int headersize;
	char filenamebak[FILENAME_MAX];
	
	// getopt_long
	struct option options[] = {
		{"repetition", 0, 0, 0},
		{"delete", 0, 0, 0},
		{"verbose", 0, 0, 0},
		{0, 0, 0, 0}
	};
	int opt;
	int optindex;

	if (sizeof(unsigned int) != FOUR_BYTE) {
		fprintf(stderr, "compile error\n");
		return EXIT_FAILURE;
	}

	// 初期化
	memset(g_filename, '\0', FILENAME_MAX);
	memset(g_del_frametype, '\0', ID3_FRAME_ID_SIZE+1);
	
	// option解析
	while ((opt = getopt_long(argc, argv, "rd:v", options, &optindex)) != -1){
		switch (opt){
		case 0: //long opt
#ifdef DEBUG_ON
			printf("optindex = %d\n", optindex);
#endif
			switch (optindex){
			case LONGOPT_REPETITION:
				g_flag |= OPTFLAG_REPETITION;
				break;
			case LONGOPT_DELETE:
				g_flag |= OPTFLAG_DELETE;
				if (!optarg)
					usage(argv[0]);
				strncpy(g_del_frametype, optarg, ID3_FRAME_ID_SIZE);
				break;
			case LONGOPT_VERBOSE:
				g_flag |= OPTFLAG_VERBOSE;
				break;
			default:
				break;
			}
			break;
		case 'r': // repetition opt
			g_flag |= OPTFLAG_REPETITION;
			break;
		case 'd': // delete opt
			g_flag |= OPTFLAG_DELETE;
			if (!optarg)
				usage(argv[0]);
			strncpy(g_del_frametype, optarg, ID3_FRAME_ID_SIZE);
			break;
		case 'v': // verbose opt
			g_flag |= OPTFLAG_VERBOSE;
			break;
		default:
			usage(argv[0]);
			break;
		}
	}
#ifdef DEBUG_ON
	printf("OPT = %02X\n", g_flag);
	printf("OPTARG = %s\n", g_del_frametype);
#endif

	// file open
	if (optind >= argc) usage(argv[0]); // to exit
	else {
		fpr = fopen(argv[optind], "rb");
		if (fpr == NULL) {
			fprintf(stderr, "file open error : %s\n", argv[optind]);
			usage(argv[0]);
		}
	}
	strncpy(g_filename, argv[optind], FILENAME_MAX);

	// 修正後のサイズを取得する
	headersize = get_id3_repair_size(fpr);
#ifdef DEBUG_ON
	printf("returnsize = %08X\n", headersize);
#endif
	if (0 == headersize) goto MAIN_EXIT_SUCCESS;
	if (RET_ERROR == headersize) goto MAIN_EXIT_FAILURE;
	fclose(fpr); // 一旦ファイルをクローズ

	// filenameのファイルを$1.bakに名前変更しfilenameで新規ファイルを作成する
	strncpy(filenamebak, argv[optind], FILENAME_MAX);
	strncat(filenamebak, ".bak", 4);
	if (rename(argv[optind], filenamebak)) goto MAIN_EXIT_FAILURE;

	fpr = fopen(filenamebak, "rb");
	if (fpr == NULL) {
		fprintf(stderr, "file open error : %s\n", filenamebak);
		goto MAIN_EXIT_FAILURE;
	}
	fpw = fopen(argv[optind], "wb");
	if (fpw == NULL) {
		fprintf(stderr, "file open error : %s\n", argv[optind]);
		goto MAIN_EXIT_FAILURE;
	}

	// タグを修正する
	if (repair_id3_tag(fpw, fpr, headersize)) goto MAIN_EXIT_FAILURE;


  MAIN_EXIT_SUCCESS:
	if(fpr != NULL) fclose(fpr);
	if(fpw != NULL) fclose(fpw);
	return EXIT_SUCCESS;
	
  MAIN_EXIT_FAILURE:
	if(fpr != NULL) fclose(fpr);
	if(fpw != NULL) fclose(fpw);
	return EXIT_FAILURE;
}


/* fpstr **********************************************
   ストリームからstr文字列(データ)を探し出す

   npos: 0以外がセットされればnpos位置までしか読み込みを行わない
   戻り値：見つかれば0、見つからないかエラーでそれ以外
   注意：一回は必ず読み出しが行われる
*******************************************************/
int fpstr(FILE *fp, const char *str, fpos_t npos) {
	char strbuf[STR_BUF];
	fpos_t pos;

	memset(strbuf, '\0', STR_BUF);

	if (fp == NULL) return RET_ERROR;
	if (strlen(str) > STR_BUF) return RET_ERROR;

#ifdef DEBUG_ON
	printf("checkpoint 2 str = %s\n", str);
#endif
	while (0 < fread(strbuf, 1, 1, fp)) {
		if (strbuf[0] == str[0]){
			if (strlen(str)-1 > fread(strbuf+1, 1, strlen(str)-1, fp)) return RET_ERROR;
#ifdef DEBUG_ON
			printf("checkpoint 3 strbuf = %s\n", strbuf);
#endif
			if (0 == strncmp(strbuf, str, strlen(str))) {
				if (fseek(fp, -(strlen(str)), SEEK_CUR)) return RET_ERROR;
				else return RET_OK;
			}
			if (fseek(fp, -(strlen(str)-1), SEEK_CUR)) return RET_ERROR;
		}
		if (fgetpos(fp, &pos)) return RET_ERROR;
		if ((npos > 0) && (pos > npos)) break;
	}
#ifdef DEBUG_ON
	printf("fpos = %08X\n", (unsigned int)pos);
#endif
	return RET_FAILURE;
}


/* fcopy **********************************************
   fprの中身をfpwにコピーする。

   戻り値：エラー-1
*******************************************************/
int fcopy(FILE *fpw, FILE *fpr) {
	size_t n;
	char buf[READ_BUF_SIZE];

	if ((fpr == NULL) || (fpw == NULL)) return RET_ERROR;

	while (1) {
		n = fread(buf, sizeof(char), READ_BUF_SIZE, fpr);

		if (n != READ_BUF_SIZE) {
			if ((n <= 0) || (n > READ_BUF_SIZE)) break;
			if (n != fwrite(buf, sizeof(char), n, fpw)) return RET_ERROR;
			break;
		}
		else
			if (n != fwrite(buf, sizeof(char), n, fpw)) return RET_ERROR;
	}

	return RET_OK;
}


/* fncopy *********************************************
   fprの中身を n byte fpwにコピーする。

   戻り値：エラー-1
*******************************************************/
int fncopy(FILE *fpw, FILE *fpr, size_t n) {
	int i;
	char buf;

	if ((fpr == NULL) || (fpw == NULL)) return RET_ERROR;

	for (i = 0; i < n; i++) {
		if (1 != fread(&buf, sizeof(char), 1, fpr)) return RET_ERROR;
		if (1 != fwrite(&buf, sizeof(char), 1, fpw)) return RET_ERROR;
	}

	return RET_OK;
}


/* read_id3_header **************
   headerに各データを読み込む

   戻り値：正常であれば0
   注意：read関数はfposを移動させる
*********************************/
int read_id3_header(ID3HEADER *header, FILE *fp) {
	if (fp == NULL) return RET_ERROR;

	// id3
	if (0 >= fread(header->id3, sizeof(header->id3), 1, fp)) return RET_ERROR;

	// version
	if (0 >= fread(header->version, sizeof(header->version), 1, fp)) return RET_ERROR;

	// flag
	if (0 >= fread(&(header->flag), sizeof(header->flag), 1, fp)) return RET_ERROR;

	// size
	if (0 >= fread(&(header->size), FOUR_BYTE, 1, fp)) return RET_ERROR;

	// sizeがsynchsafeと同じ形式であるため変換する
	header->size = FROM_SYNCHSAFE(header->size);

#ifdef DEBUG_ON
	printf("id3 = %c%c%c\n", header->id3[0], header->id3[1], header->id3[2]);
	printf("version = %02X%02X\n", header->version[0], header->version[1]);
	printf("flag = %02X\n", header->flag);
	printf("size = %08X\n", header->size);
	printf("size(original) = %08X\n", REVERSE_ENDIAN(TO_SYNCHSAFE(header->size)));
#endif

	return RET_OK;
}


/* read_id3_extheader **************
   headerに各データを読み込む

   戻り値：正常であれば0
   注意：read関数はfposを移動させる
************************************/
int read_id3_extheader(ID3EXTHEADER *header, FILE *fp) {
	if (fp == NULL) return RET_ERROR;

	// size
	if (0 >= fread(&(header->size), FOUR_BYTE, 1, fp)) return RET_ERROR;

	// flag
	if (0 >= fread(header->flag, sizeof(header->flag), 1, fp)) return RET_ERROR;

	// padding_size
	if (0 >= fread(&(header->padding_size), FOUR_BYTE, 1, fp)) return RET_ERROR;

	// crcフラグチェック
	if (header->flag[0] & EXT_FLAG_CRC) {
		// crc 読み込み
		if (0 >= fread(header->crc, sizeof(header->crc), 1, fp)) return RET_ERROR;
	}

	// size,padding_sizeがビッグエンディアンのためリトルエンディアンに変換する
	header->size = REVERSE_ENDIAN(header->size);
	header->padding_size = REVERSE_ENDIAN(header->padding_size);

#ifdef DEBUG_ON
	printf("size = %08X\n", header->size);
	printf("size(original) = %08X\n", REVERSE_ENDIAN(header->size));
	printf("extflag = %02X%02X\n", header->flag[0], header->flag[1]);
	printf("padding_size = %08X\n", header->padding_size);
	printf("padding_size(original) = %08X\n", REVERSE_ENDIAN(header->padding_size));
	printf("crc = %c%c%c%c\n", header->crc[0], header->crc[1], header->crc[2], header->crc[3]);
#endif

	return RET_OK;
}


/* read_id3_frame_header *********************
   headerに各データを読み込む

   戻り値：正常であれば0
   注意：read関数はfposを移動させる
**********************************************/
int read_id3_frame_header(ID3FRAMEHEADER *header, FILE *fp) {
	if (fp == NULL) return RET_ERROR;

	// id
	if (0 >= fread(header->id, sizeof(header->id), 1, fp)) return RET_ERROR;

	// size
	if (0 >= fread(&(header->size), FOUR_BYTE, 1, fp)) return RET_ERROR;

	// flag
	if (0 >= fread(&(header->flag), sizeof(header->flag), 1, fp)) return RET_ERROR;

	// sizeがビッグエンディアンのためリトルエンディアンに変換する
	header->size = REVERSE_ENDIAN(header->size);

#ifdef DEBUG_ON
	printf("id = %c%c%c%c\n", header->id[0], header->id[1], header->id[2], header->id[3]);
	printf("size = %08X\n", header->size);
	printf("size(original) = %08X\n", REVERSE_ENDIAN(header->size));
	printf("flag = %02X%02X\n", header->flag[0], header->flag[1]);
#endif

	return RET_OK;
}


/* write_id3 header **************
   戻り値：正常0 エラー1
*****************************************/
int write_id3_header(const ID3HEADER *header, FILE *fp) {
	unsigned int headersize;

	if (fp == NULL) return RET_ERROR;

	// synchsafe形式に変換する
	headersize = TO_SYNCHSAFE(header->size);

	if (1 != fwrite(header->id3, sizeof(header->id3), 1, fp)) return RET_ERROR;
	if (1 != fwrite(header->version, sizeof(header->version), 1, fp)) return RET_ERROR;
	if (1 != fwrite(&(header->flag), sizeof(header->flag), 1, fp)) return RET_ERROR;
	if (1 != fwrite(&headersize, FOUR_BYTE, 1, fp)) return RET_ERROR;

#ifdef DEBUG2_ON
	printf("header->size = %08X : headersize = %08X\n", header->size, headersize);
	printf("id3s = %d : vers = %d : flas = %d : sizs = %d\n", sizeof(header->id3), sizeof(header->version), sizeof(header->flag), sizeof(header->size));
#endif
	
	return RET_OK;
}


/* write_id3 extheader ******************
   戻り値：正常0 エラー1
*****************************************/
int write_id3_extheader(const ID3EXTHEADER *header, FILE *fp) {
	unsigned int headersize;
	unsigned int paddingsize;
	
	if (fp == NULL) return RET_ERROR;
	
	// リトルエンディアンをビッグエンディアンに戻す
	headersize = REVERSE_ENDIAN(header->size);
	paddingsize = REVERSE_ENDIAN(header->padding_size);

	if (1 != fwrite(&headersize, FOUR_BYTE, 1, fp)) return RET_ERROR;
	if (1 != fwrite(header->flag, sizeof(header->flag), 1, fp)) return RET_ERROR;
	if (1 != fwrite(&paddingsize, FOUR_BYTE, 1, fp)) return RET_ERROR;

	if (header->flag[0] & EXT_FLAG_CRC) {
		if (1 != fwrite(header->crc, sizeof(header->crc), 1, fp)) return RET_ERROR;
	}

	return RET_OK;
}


/* write_id3 frame *****************************
   戻り値：正常0 エラー1
************************************************/
int write_id3_frame(const ID3FRAMEHEADER *header, FILE *fpr, FILE *fpw) {
	unsigned int headersize;

	if ((fpr == NULL) || (fpw == NULL)) return RET_ERROR;

	// リトルエンディアンをビッグエンディアンに戻す
	headersize = REVERSE_ENDIAN(header->size);

	if (1 != fwrite(header->id, sizeof(header->id), 1, fpw)) return RET_ERROR;
	if (1 != fwrite(&headersize, FOUR_BYTE, 1, fpw)) return RET_ERROR;
	if (1 != fwrite(&(header->flag), sizeof(header->flag), 1, fpw)) return RET_ERROR;

	// frameのデータ部分をコピー
	if (fncopy(fpw, fpr, header->size)) return RET_ERROR;
	
	return RET_OK;
}


/* write_id3 repair_apic_frame **********
   戻り値：正常0 エラー1
*****************************************/
int write_id3_repair_apic_frame(const ID3FRAMEHEADER *header, FILE *fpr, FILE *fpw) {
	unsigned int headersize;
	unsigned char buf;

	if ((fpr == NULL) || (fpw == NULL)) return RET_ERROR;

	headersize = header->size -1;
	headersize = REVERSE_ENDIAN(headersize);	// リトルエンディアンをビッグエンディアンに戻す

	if (1 != fwrite(header->id, sizeof(header->id), 1, fpw)) return RET_ERROR;
	if (1 != fwrite(&headersize, FOUR_BYTE, 1, fpw)) return RET_ERROR;
	if (1 != fwrite(&(header->flag), sizeof(header->flag), 1, fpw)) return RET_ERROR;

	//  encodeと"ima"までコピー
	if (fncopy(fpw, fpr, 4)) return RET_ERROR;

	// ゴミチェック
	if (1 != fread(&buf, 1, 1, fpr)) return RET_ERROR;
	if (buf != 0) {
		fprintf(stderr, "not [ima ge]. char is %c (%02X).\n", buf, buf);
		return RET_ERROR;
	}

	// 残りデータ部分をコピー(コピーされた4byteとゴミの分をsizeから引く）
	if (fncopy(fpw, fpr, (header->size -4 -1))) return RET_ERROR;

	return RET_OK;
}


/* seek id3_next_frame ******************
   戻り値：正常0 エラー1
*****************************************/
int seek_id3_next_frame(FILE *fp, const ID3FRAMEHEADER *header) {
	if (fp == NULL) return RET_ERROR;
	if (fseek(fp, header->size, SEEK_CUR)) return RET_ERROR;
	
	return RET_OK;
}


/* get_id3_apic_type ********************
   apictypeにapictypeをセットする
   戻り値：正常0 エラー-1
*****************************************/
int get_id3_apic_type(FILE *fp, unsigned char *apictype) {
	ID3APICFRAME apicframe;
	fpos_t pos;
	int cnt = 0;

	if (fp == NULL) return RET_ERROR;
	if (fgetpos(fp, &pos)) return RET_ERROR;

	if (0 >= fread(&(apicframe.encode), 1, 1, fp)) goto GET_ID3_APIC_TYPE_ERROR;
	// ゴミがある場所まで先に読み込む
	if (0 >= fread(apicframe.mimetype, 1, 4, fp)) goto GET_ID3_APIC_TYPE_ERROR;
	cnt = 4;

	// mimetype読み込み
	while (0 < fread(&apicframe.mimetype[cnt], 1, 1, fp)) {
		if (apicframe.mimetype[cnt] == 0) break;
		if (cnt >= MIMETYPE_MAXSIZE) goto GET_ID3_APIC_TYPE_ERROR;
		cnt++;
	}

	// typeを読み込む
	if (0 >= fread(apictype, 1, 1, fp)) goto GET_ID3_APIC_TYPE_ERROR;	

	if (*apictype >= PICTURE_TYPE_NUM) {
		fprintf(stderr, "This APIC type (%02X) is undefined.\n", *apictype);
		goto GET_ID3_APIC_TYPE_ERROR;
	}
	
	if (fseek(fp, pos, SEEK_SET)) return RET_ERROR;

#ifdef DEBUG2_ON
	printf("pictype = %02X\n", *apictype);
#endif
	return RET_OK;

  GET_ID3_APIC_TYPE_ERROR:
	if (fseek(fp, pos, SEEK_SET)) return RET_ERROR;
	return RET_ERROR;	
}
	

/* check_id3_mime_type ******************
   mimetype が "ima ge"となっていないかチェックする
   fposは初期状態に戻される

   戻り値：正常0 修正1 エラー-1
*****************************************/
int check_id3_mime_type(FILE *fp) {
	ID3APICFRAME apicframe;
	fpos_t pos;
	int cnt = 0;

	if (fp == NULL) return RET_ERROR;
	if (fgetpos(fp, &pos)) return RET_ERROR;

	if (0 >= fread(&(apicframe.encode), 1, 1, fp)) goto CHECK_ID3_MIME_TYPE_ERROR;
	if (0 >= fread(apicframe.mimetype, 1, 4, fp)) goto CHECK_ID3_MIME_TYPE_ERROR;

	cnt = 4;

	// ゴミチェック
	if (apicframe.mimetype[cnt-1] == 0) {
		if (fseek(fp, pos, SEEK_SET)) return RET_ERROR;
		return RET_FAILURE;
	}

	// mimetype読み込み
	while (0 < fread(&apicframe.mimetype[cnt], 1, 1, fp)) {
		if (apicframe.mimetype[cnt] == 0) break;
		if (cnt >= MIMETYPE_MAXSIZE) goto CHECK_ID3_MIME_TYPE_ERROR;
		cnt++;
	}

	if (fseek(fp, pos, SEEK_SET)) return RET_ERROR;
#ifdef DEBUG_ON
	printf("mimetype = %s\n", apicframe.mimetype);
#endif
	return RET_OK;

  CHECK_ID3_MIME_TYPE_ERROR:
	if (fseek(fp, pos, SEEK_SET)) return RET_ERROR;
	return RET_ERROR;	
}


/* check_id3_tag *******************************
   ID3V2.3形式のファイルであるか確認する

   戻り値：ID3V2.3,1  Not,0
************************************************/
int check_id3_tag(const ID3HEADER *header) {
	if (0 != strncmp(header->id3, ID3_HEADER_ID_CHECK, ID3_HEADER_ID_SIZE)) return 0;
	if (header->version[0] != ID3_HEADER_VERSION_CHECK) return 0;
	
	return 1;
}


/* get_id3_repair_size ******************
   修正する必要がなければ 0 を返す

   戻り値：修正後予想タグサイズ
*****************************************/
unsigned int get_id3_repair_size(FILE *fp) {
	ID3HEADER header;
	ID3EXTHEADER extheader;
	ID3FRAMEHEADER frameheader;
	unsigned char apictypeflag[PICTURE_TYPE_NUM];  // 同一pictypeを検出するためにフラグを立てる
	unsigned char apictype;
	unsigned int repairsize = 0;
	fpos_t pos;
	unsigned int ret;

	memset(&extheader, 0, sizeof(extheader));
	memset(apictypeflag, 0, PICTURE_TYPE_NUM);
	
	// ヘッダ読み込み
	if (read_id3_header(&header, fp)) return RET_ERROR;
	if (! check_id3_tag(&header)) {
		fprintf(stderr, "It doesn't correspond to this file format. Please let me read the file of the ID3v2.3 form. \n");
		return RET_ERROR;
	}
	repairsize = header.size;

	// 拡張ヘッダ読み込み
	if (header.flag & FLAG_EXT) {
		if (read_id3_extheader(&extheader, fp)) return RET_ERROR;
		if (extheader.flag[0] & EXT_FLAG_CRC) {
			fprintf(stderr, "It doesn't correspond to CRC.\n");
			return RET_ERROR;
		}
	}

	// フレーム読み込み
	do {
#ifdef DEBUG_ON
		printf("repairsize = %08X\n", repairsize);
#endif
		if (read_id3_frame_header(&frameheader, fp)) return RET_ERROR;

		if (frameheader.id[0] == 0) break; // padding領域侵入

		// 削除対称フレームタイプチェック
		if (g_flag & OPTFLAG_DELETE) {
			if (0 == strncmp(frameheader.id, g_del_frametype, ID3_FRAME_ID_SIZE)) {
				repairsize -= ID3_FRAME_SIZE + frameheader.size;
				if (seek_id3_next_frame(fp, &frameheader)) return RET_ERROR;
				fgetpos(fp, &pos);
#ifdef DEBUG_ON
		printf("delete %c%c%c%c frame\n", frameheader.id[0], frameheader.id[1], frameheader.id[2], frameheader.id[3]);
#endif
				continue;
			}
		}

		// APICの場合には重複とMIMETYPEをチェックする
		if (0 == strncmp(frameheader.id, ID3_FRAME_ID_PIC, ID3_FRAME_ID_SIZE)) {
			if (g_flag & OPTFLAG_REPETITION) {
				if (get_id3_apic_type(fp, &apictype)) return RET_ERROR;
				if (apictypeflag[apictype]) {
					repairsize -= ID3_FRAME_SIZE + frameheader.size;
					if (seek_id3_next_frame(fp, &frameheader)) return RET_ERROR;
					fgetpos(fp, &pos);
#ifdef DEBUG_ON
					printf("delete repetition APIC\n");
#endif
					continue;
				}
				apictypeflag[apictype] = 1;
			}

			ret = check_id3_mime_type(fp);
			if (ret == 1) repairsize--;
			else if (ret != 0) return RET_ERROR;
		}

		if (seek_id3_next_frame(fp, &frameheader)) return RET_ERROR;
		fgetpos(fp, &pos);
#ifdef DEBUG_ON
		printf("endsize = %08X\n", (header.size - extheader.padding_size + ID3_HEADER_SIZE));
		printf("pos = %08X\n", (unsigned int)pos);
#endif
	} while (header.size - extheader.padding_size + ID3_HEADER_SIZE >= pos); // padding領域かDATA領域に来るまでフレームを読む

	if (repairsize == header.size) repairsize = 0;
	
	return repairsize;
}


/* repair_id3_tag *****************************
   id3タグを修正する

   戻り値：成否(成功：0　失敗：-1)
   注意：事前にget_id3_repair_sizeを実行して
         headersizeを取得しておく必要がある
***********************************************/
int repair_id3_tag(FILE *fpw, FILE *fpr, unsigned int headersize) {
	ID3HEADER header;
	ID3EXTHEADER extheader;
	ID3FRAMEHEADER frameheader;
	unsigned char apictypeflag[PICTURE_TYPE_NUM];  // 同一pictypeを検出するためにフラグを立てる
	unsigned char apictype;
	fpos_t pos;
	unsigned int ret, oldheadersize;

	memset(&extheader, 0, sizeof(extheader));
	memset(apictypeflag, 0, PICTURE_TYPE_NUM);
	
	// ヘッダ
	if (read_id3_header(&header, fpr)) return RET_ERROR;
	oldheadersize = header.size;
	header.size = headersize; 	// ヘッダサイズを修正後の値に変更
	if (write_id3_header(&header, fpw)) return RET_ERROR;
	

	// 拡張ヘッダ
	if (header.flag & FLAG_EXT) {
		if (read_id3_extheader(&extheader, fpr)) return RET_ERROR;
		if (extheader.flag[0] & EXT_FLAG_CRC) {
			fprintf(stderr, "It doesn't correspond to CRC.\n");
			return RET_ERROR;
		}
		if (write_id3_extheader(&extheader, fpw)) return RET_ERROR;
	}

	// フレーム
	do {
		if (read_id3_frame_header(&frameheader, fpr)) return RET_ERROR;

		// padding領域侵入
		if (frameheader.id[0] == 0) {
			if (ID3_FRAME_SIZE != fwrite(&(frameheader.id[0]), 1, ID3_FRAME_SIZE, fpw)) return RET_ERROR;
			break;
		}

		// 削除対称フレームタイプチェック
		if (g_flag & OPTFLAG_DELETE) {
			if (0 == strncmp(frameheader.id, g_del_frametype, ID3_FRAME_ID_SIZE)) {
				// 削除情報出力
				if (g_flag & OPTFLAG_VERBOSE) {
					fgetpos(fpr, &pos);
					printf("%s : delete frame (%s) %08X - %08X\n",
						   g_filename, g_del_frametype, (unsigned int)pos-10, (unsigned int)pos+frameheader.size);
				}
				if (seek_id3_next_frame(fpr, &frameheader)) return RET_ERROR;
				fgetpos(fpr, &pos);
				continue;
			}
		}

		// APICの場合には重複とMIMETYPEをチェックする
		if (0 == strncmp(frameheader.id, ID3_FRAME_ID_PIC, ID3_FRAME_ID_SIZE)) {
			if (g_flag & OPTFLAG_REPETITION) {
				if (get_id3_apic_type(fpr, &apictype)) return RET_ERROR;
				if (apictypeflag[apictype]) {
					// 削除情報出力
					if (g_flag & OPTFLAG_VERBOSE) {
						fgetpos(fpr, &pos);
						printf("%s : delete frame (%s) %08X - %08X\n",
							   g_filename, ID3_FRAME_ID_PIC, (unsigned int)pos-10, (unsigned int)pos+frameheader.size);
					}
					if (seek_id3_next_frame(fpr, &frameheader)) return RET_ERROR;
					fgetpos(fpr, &pos);
					continue;
				}
				apictypeflag[apictype] = 1;
			}

			ret = check_id3_mime_type(fpr);
			if (ret == 1) {
				// 削除情報出力
				if (g_flag & OPTFLAG_VERBOSE) {
					fgetpos(fpr, &pos);
					printf("%s : repair APIC frame (ima ge->image) %08X - %08X\n",
						   g_filename, (unsigned int)pos-10, (unsigned int)pos+frameheader.size);
				}
				if (write_id3_repair_apic_frame(&frameheader, fpr, fpw)) return RET_ERROR;
				fgetpos(fpr, &pos);
				continue;
			}
			else if (ret != 0) return RET_ERROR;
		}

		if (write_id3_frame(&frameheader, fpr, fpw)) return RET_ERROR;
		fgetpos(fpr, &pos);
#ifdef DEBUG2_ON
		printf("endsize = %08X\n", (oldheadersize - extheader.padding_size + ID3_HEADER_SIZE));
		printf("pos = %08X\n", (unsigned int)pos);
#endif		
	} while (oldheadersize - extheader.padding_size + ID3_HEADER_SIZE >= pos); // padding領域かDATA領域に来るまでフレームを読む

	// パディング領域、データ領域をコピーする
	fcopy(fpw, fpr);
	
	return RET_OK;
}

