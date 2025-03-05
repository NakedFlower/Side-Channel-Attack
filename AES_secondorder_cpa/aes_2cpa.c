#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>

#define  _FOLD_ "C:\\Users\\ATIV\\Desktop\\학부연구생\\"
#define TraceFN  "2022.02.21-07.39.04_traces.npy"
#define AlignedTraceFN "AlignedAES.traces"
#define PlaintextFN "2022.02.21-07.39.04_textin.npy"
#define CiphertextFN "ciphertext.txt"
#define startpoint 0
#define endpoint 24000

static unsigned char Sbox[256] = {
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

double cov(double* x, double* y, int size) {

	double Sxy = 0, Sx = 0, Sy = 0;
	int i;

	for (i = 0; i < size; i++) {
		Sxy += (double)x[i] * y[i];      //E(XY)
		Sx += x[i];      //E(X)
		Sy += y[i];      //E(Y)
	}
	return (Sxy - Sx * Sy / (double)size) / (double)size;
}

double corr(double* x, double* y, int size) {

	double Sxy = 0, Sx = 0, Sy = 0, Sxx = 0, Syy = 0;      //var(X) = E(X^2) - E(X)^2
	int i;

	for (i = 0; i < size; i++) {
		Sxy += (double)x[i] * y[i];      //E(XY)
		Sx += x[i];      //E(X)
		Sy += y[i];      //E(Y)
		Sxx += (double)x[i] * x[i];
		Syy += (double)y[i] * y[i];
	}
	return ((double)size * Sxy - Sx * Sy) / sqrt(((double)size * Sxx - Sx * Sx) * ((double)size * Syy - Sy * Sy));
	//var(x) == Sxx/(double)size - Sx*Sx/(double)size/(double)size)
}      //상관계수 

void subalign(double* data, double* data1, int windowsize, int stepsize, int threshold, int TraceLength) {

	int i, j, size, maxcovpos, k;
	double* x, * y;
	double covval, maxcov;

	for (i = 0; i < (TraceLength - windowsize); i += stepsize) {

		maxcovpos = 0;
		maxcov = 0;

		for (j = -threshold; j < threshold; j++) {

			if (j < 0) {
				x = data + i;
				y = data1 + i - j;
				size = windowsize + j;
			}
			else {
				x = data + i + j;
				y = data + i;
				size = windowsize - j;
			}
			covval = cov(x, y, size);

			if (covval > maxcov) {
				maxcovpos = j;
				maxcov = covval;
			}
		}
		if (maxcovpos < 0) {
			for (k = i; k < (TraceLength + maxcovpos); k++) {
				data1[k] = data1[k - maxcovpos];
			}
		}
		else {
			for ((k = TraceLength - maxcovpos - 1); k >= i; k--) {
				data1[k + maxcovpos] = data1[k];
			}
		}
	}
}      //data 배열에 저장되어 있는 전력 파형을 기준으로 data1 배열에 저장되어 있는 전력 파형을 정렬

void Alignment() {
	int windowsize = 500;      //정렬을 맞추고 싶은 파형의 길이
	int stepsize = 450;      //한 부분의 정렬을 맞춘 후에 몇 포인트씩 이동후 다시 정렬을 맞출 것인지 결정
	int threshold = 100;      //좌우로 얼마나 흔들면서 cov값을 계산해서 최대값과 이동할 포인트수를 계산

	char buf[256];
	int err, TraceLength, TraceNum;
	FILE* rfp, * wfp;

	double* data, * data1;

	sprintf_s(buf, 256 * sizeof(char), "%s%s", _FOLD_, TraceFN);
	if ((err = fopen_s(&rfp, buf, "rb")))
	{
		printf("File Open Error!!\n");
		exit(1);
	}

	sprintf_s(buf, 256 * sizeof(char), "%s%s", _FOLD_, AlignedTraceFN);
	if ((err = fopen_s(&wfp, buf, "wb")))
	{
		printf("File Open Error!!\n");
		exit(1);
	}

	fread(&TraceLength, sizeof(int), 1, rfp);
	fwrite(&TraceLength, sizeof(int), 1, wfp);
	fread(&TraceNum, sizeof(int), 1, rfp);
	fwrite(&TraceNum, sizeof(int), 1, wfp);      //처음 4바이트와 그 다음 4바이트에 담겨 있는 파형 길이와 갯수

	data = (double*)calloc(TraceLength, sizeof(double));
	data1 = (double*)calloc(TraceLength, sizeof(double));      //data와 data1에 대한 버퍼를 TraceLength만큼 double형태로 메모리를 할당해준 것

	fread(data, sizeof(double), TraceLength, rfp);
	fwrite(data, sizeof(double), TraceLength, wfp);      //첫번째 파형

	for (int i = 1; i < TraceNum; i++) {
		fread(data1, sizeof(double), TraceLength, rfp);
		subalign(data, data1, windowsize, stepsize, threshold, TraceLength);
		fwrite(data1, sizeof(double), TraceLength, wfp);
	}

	fclose(rfp);
	fclose(wfp);

	free(data);
	free(data1);
}

void CPA_Plain() {
	unsigned char** plaintext = NULL; //2000개의 16byte의 평문을 2000 * 16 크기의 배열에 저장
	double** data;   //정렬된 파형을 한번에 메모리에 올려서 작업
	unsigned char temp[34], x, y, iv, hm_iv;
	char buf[256];
	double* Sx, * Sxx, * Sxy, * corrT;
	double Sy, Syy, max;
	int err, TraceLength = 24000, TraceNum = 5000, i, j, k, key, maxkey;
	FILE* rfp, * wfp;

	sprintf_s(buf, 256 * sizeof(char), "%s%s", _FOLD_, TraceFN);
	if ((err = fopen_s(&rfp, buf, "rb")))
	{
		printf("File Open Error1!!\n");
		exit(1);
	}

	data = (double**)calloc(TraceNum, sizeof(double*));
	for (i = 0; i < TraceNum; i++) {
		data[i] = (double*)calloc(TraceLength, sizeof(double));

	} // 공간을 선언
	for (i = 0; i < TraceNum; i++) {
		fread(data[i], sizeof(double), TraceLength, rfp);
	}// trace 읽는다. 
	fclose(rfp);

	sprintf_s(buf, 256 * sizeof(char), "%s%s", _FOLD_, PlaintextFN);
	if ((err = fopen_s(&rfp, buf, "rb")))
	{
		printf("File Open Error2!!\n");
		exit(1);
	}
	plaintext = (unsigned char**)calloc(TraceNum, sizeof(unsigned char*));
	for (i = 0; i < TraceNum; i++) {
		plaintext[i] = (unsigned char*)calloc(16, sizeof(unsigned char));
	}
	for (i = 0; i < TraceNum; i++) {
		fread(plaintext[i], sizeof(char), 16, rfp);
	}
	fclose(rfp);

	Sx = (double*)calloc(TraceLength, sizeof(double));
	Sxx = (double*)calloc(TraceLength, sizeof(double));
	Sxy = (double*)calloc(TraceLength, sizeof(double));
	corrT = (double*)calloc(TraceLength, sizeof(double));

	for (i = 0; i < TraceNum; i++) {
		for (j = startpoint; j < endpoint; j++) {
			Sx[j] += data[i][j];
			Sxx[j] += data[i][j] * data[i][j];
		}
	}

	for (int b = 0; b < 16; b++) {
		Sy = 0;
		Syy = 0;
		memset(Sxy, 0, sizeof(double) * TraceLength);

		for (j = 0; j < TraceNum; j++) {
			iv = plaintext[j][b];
			hm_iv = 0;

			for (k = 0; k < 8; k++) {
				hm_iv += ((iv >> k) & 1);
			}

			Sy += hm_iv;
			Syy += hm_iv * hm_iv;

			for (k = startpoint /*0*/; k < endpoint /*TraceLength*/; k++) {
				Sxy[k] += hm_iv * data[j][k];
			}
			for (k = startpoint /*0*/; k < endpoint /*TraceLength*/; k++) {
				corrT[k] = ((double)TraceNum * Sxy[k] - Sx[k] * Sy) / sqrt(((double)TraceNum * Sxx[k] - Sx[k] * Sx[k]) * ((double)TraceNum * Syy - Sy * Sy));
			}
		}
		sprintf_s(buf, 256 * sizeof(char), "%scpa\\cpa%02x.corrtrace", _FOLD_, b);
		if ((err = fopen_s(&wfp, buf, "wb"))) {
			printf("File Open Error5!!\n");
		}

		fwrite(corrT, sizeof(double), TraceLength, wfp);
		fclose(wfp);
		printf("%d round finish", b);
	}
	free(Sx);
	free(Sxx);
	free(Sxy);
	free(corrT);
	free(data);
	free(plaintext);
	/*
	for (i = 0; i < 16; i++) {
		Sy = 0;
		Syy = 0;
		memset(Sxy, 0, sizeof(double) * TraceLength);
		for (j = 0; j < TraceNum; j++) {
			iv = plaintext[j][i];
			hm_iv = 0;
			for (k = 0; k < 8; k++) {
				hm_iv += ((iv >> k) & 1);
			}
			Sy += hm_iv;
			Syy += hm_iv * hm_iv;
			for (k = startpoint; k < endpoint; k++) {
				Sxy[k] += hm_iv * data[j][k];
			}
		}
		for (k = startpoint; k < endpoint; k++) {
			corrT[k] = ((double)TraceNum * Sxy[k] - Sx[k] * Sy) / sqrt(((double)TraceNum * Sxx[k] - Sx[k] * Sx[k]) * ((double)TraceNum * Syy - Sy * Sy));
		}

		sprintf_s(buf, 256 * sizeof(char), "%splaintextcpa\\cpa_%02d.corrtrace", _FOLD_, i);
		if (( err = fopen_s(&wfp, buf, "wb")))
		{
			printf("File Open Error3!!\n");
		}
		fwrite(corrT, sizeof(double), TraceLength, wfp);
		fclose(wfp);
	}
	free(Sx);
	free(Sxx);
	free(Sxy);
	free(corrT);
	free(data);
	free(plaintext);
	*/
}

void secondordercpa() {
	unsigned char** plaintext = NULL; //2000개의 16byte의 평문을 2000 * 16 크기의 배열에 저장
	double** data = NULL;   //정렬된 파형을 한번에 메모리에 올려서 작업
	double* data_ave = NULL;
	double** data_final = NULL, ** Cut1;
	unsigned char iv, hm_iv;
	char buf[256];
	double* Sx = NULL, * Sxx = NULL, * Sxy = NULL, * corrT = NULL, ** MultT = NULL;
	double Sy, Syy, max;
	int err, TraceLength = 24000, TraceNum = 5000, i, j, k, key, maxkey;
	FILE* rfp, * wfp;
	int s_msbox = 18250;
	int e_msbox = 18450;
	int s_msub = 2800;
	int e_msub = 3000;
	int len = (e_msub - s_msub) * (e_msbox - s_msbox);
	double* SUM = NULL;

	sprintf_s(buf, 256 * sizeof(char), "%s%s", _FOLD_, TraceFN);
	if ((err = fopen_s(&rfp, buf, "rb")))
	{
		printf("File Open Error1!!\n");
		exit(1);
	}

	data = (double**)calloc(TraceNum, sizeof(double*));
	for (i = 0; i < TraceNum; i++) {
		data[i] = (double*)calloc(TraceLength, sizeof(double));

	} // 공간을 선언
	for (i = 0; i < TraceNum; i++) {
		fread(data[i], sizeof(double), TraceLength, rfp);
	}// trace 읽는다. 
	fclose(rfp);

	sprintf_s(buf, 256 * sizeof(char), "%s%s", _FOLD_, PlaintextFN);
	if ((err = fopen_s(&rfp, buf, "rb")))
	{
		printf("File Open Error2!!\n");
		exit(1);
	}

	plaintext = (unsigned char**)calloc(TraceNum, sizeof(unsigned char*));
	for (i = 0; i < TraceNum; i++) {
		plaintext[i] = (unsigned char*)calloc(16, sizeof(unsigned char));
	}
	for (i = 0; i < TraceNum; i++) {
		fread(plaintext[i], sizeof(unsigned char), 16, rfp);
	}// trace 읽는다. 
	fclose(rfp);

	SUM = (double*)calloc(TraceLength, sizeof(double));
	data_ave = (double*)calloc(TraceLength, sizeof(double));
	data_final = (double**)calloc(TraceNum, sizeof(double*));
	for (i = 0; i < TraceNum; i++) {
		data_final[i] = (double*)calloc(TraceLength, sizeof(double));

	} // 공간을 선언
	for (i = 0; i < TraceNum; i++) {
		for (j = startpoint; j < endpoint; j++) {
			SUM[j] += data[i][j];
		}
	}
	for (int i = 0; i < TraceLength; i++) {
		data_ave[i] = SUM[i] / TraceNum;
	}      //평균 파형

	for (int i = 0; i < TraceNum; i++) {
		for (int j = 0; j < TraceLength; j++) {
			data_final[i][j] = data[i][j] - data_ave[j];
		}
	}      //파형에서 평균 파형을 뺀 파형들

	MultT = (double**)calloc(TraceNum, sizeof(double*));
	for (i = 0; i < TraceNum; i++) {
		MultT[i] = (double*)calloc(len, sizeof(double));

	} // 공간을 선언

	int n = 0;
	for (int i = 0; i < TraceNum; i++) {
		for (int j = s_msbox; j < e_msbox; j++) {
			for (int k = s_msub; k < e_msub; k++) {
				MultT[i][n] = data_final[i][j] * data_final[i][k];
				n++;
			}
		}
		n = 0;
	}
	free(data_final);
	free(SUM);
	free(data_ave);

	Sx = (double*)calloc(len, sizeof(double));
	Sxx = (double*)calloc(len, sizeof(double));
	Sxy = (double*)calloc(len, sizeof(double));
	corrT = (double*)calloc(len, sizeof(double));

	for (i = 0; i < TraceNum; i++) {
		for (j = 0; j < len; j++) {
			Sx[j] += MultT[i][j];
			Sxx[j] += MultT[i][j] * MultT[i][j];
		}
	}

	for (i = 0; i < 16; i++) {
		max = 0;
		maxkey = 0;
		for (key = 0; key < 256; key++) {
			Sy = 0;
			Syy = 0;
			memset(Sxy, 0, sizeof(double) * len);
			for (j = 0; j < TraceNum; j++) {
				iv = Sbox[plaintext[j][i] ^ key];
				hm_iv = 0;
				for (k = 0; k < 8; k++) {
					hm_iv += ((iv >> k) & 1);
				}
				Sy += hm_iv;
				Syy += hm_iv * hm_iv;
				for (k = 0; k < len; k++) {
					Sxy[k] += hm_iv * MultT[j][k];
				}
			}
			for (k = 0; k < len; k++) {
				corrT[k] = ((double)TraceNum * Sxy[k] - Sx[k] * Sy) / sqrt(((double)TraceNum * Sxx[k] - Sx[k] * Sx[k]) * ((double)TraceNum * Syy - Sy * Sy));
				if (fabs(corrT[k]) > max) {
					maxkey = key;
					max = fabs(corrT[k]);
				}
			}
			sprintf_s(buf, 256 * sizeof(char), "%scorrtrace2\\%02dth_block_%02x.corrtrace", _FOLD_, i, key);
			if ((err = fopen_s(&wfp, buf, "wb")))
			{
				printf("File Open Error3!!\n");
			}
			fwrite(corrT, sizeof(double), len, wfp);
			fclose(wfp);
			printf(".");
		}
		printf("%02dth_block : maxkey(%02x), maxcorr(%lf)\n", i, maxkey, max);
	}

	free(Sx);
	free(Sxx);
	free(Sxy);
	free(corrT);
	free(data);
	free(plaintext);
	free(MultT);
}

int main() {

	//CPA_Plain();
	secondordercpa();
	return 0;
}