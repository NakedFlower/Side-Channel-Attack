#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include "api.h"
#include "asconp.h"
#include "config.h"

#define  _FOLD_ "D:\\Isap\\"
#define TraceFN  "2022.08.17-08.52.47_traces.npy"
#define PlaintextFN "2022.08.17-08.52.47_textin.npy"
#define CiphertextFN "ciphertext.txt"
#define startpoint 0
#define endpoint 12000

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

void CPA_Plain() {
	unsigned char** plaintext = NULL; //2000개의 16byte의 평문을 2000 * 16 크기의 배열에 저장
	double** data;   //정렬된 파형을 한번에 메모리에 올려서 작업
	unsigned char temp[34], x, y, iv, hm_iv;
	char buf[256];
	double* Sx, * Sxx, * Sxy, * corrT;
	double Sy, Syy, max;
	int err, TraceLength = 12000, TraceNum = 10000, i, j, k, key, maxkey;
	FILE* rfp, * wfp;
	int count = 0;
	unsigned char* nonce_y = NULL;

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

	nonce_y = (unsigned char*)calloc(TraceNum, sizeof(unsigned char));

	unsigned char	k_key[CRYPTO_KEYBYTES] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
	unsigned char   ad[ASSOCIATED_DATA_LENGTH] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
														17,18,19,20,21,22,23,24,25,26,27,28,29,30,31 };
	unsigned char   c[MESSAGE_LENGTH + CRYPTO_ABYTES] = { 0x2C,0xDE,0x28,0xDB,0xBB,0xD9,0x13,0x1E,0xBC,
																0x56,0x8D,0x77,0x72,0x5B,0x25,0x93,0x7C,0xF8,0xED,0xB8,
																	0xA8,0xF5,0x0A,0x2A,0xCE,0xDA,0x35,0x6C,0x3C,0xA3,0xD4,0x6B,
																		0xAF,0x83,0xB9,0x60,0x92,0x8F,0x1E,0x4C,0xC9,0x75,0xEA,0x24,0xF4,0x88,0x20,0x2C };
	unsigned long long adlen = ASSOCIATED_DATA_LENGTH;
	unsigned long long clen = 0x20;
	for (int i = 0; i < TraceNum; i++) {

		const uint8_t* npub = plaintext[i];

		state_t state;
		state_t* s = &state;

		// Initialize
		s->l[0] = U64TOWORD(*(lane_t*)(npub + 0));
		s->l[1] = U64TOWORD(*(lane_t*)(npub + 8));
		s->l[2] = U64TOWORD(*(lane_t*)(ISAP_IV_A + 0));
		s->x[3] = 0;
		s->x[4] = 0;
		P_sH;

		// Absorb associated data
		ABSORB_LANES(s, ad, adlen);

		// Domain seperation
		s->w[4][0] ^= 0x1UL;

		// Absorb ciphertext
		ABSORB_LANES(s, c, clen);

		// Derive KA*
		s->l[0] = WORDTOU64(s->l[0]);
		s->l[1] = WORDTOU64(s->l[1]);

		nonce_y[i] = s->b[0][0];
	}

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

	Sy = 0;
	Syy = 0;
	memset(Sxy, 0, sizeof(double) * TraceLength);

	for (j = 0; j < TraceNum; j++) {
		iv = nonce_y[j];
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
	sprintf_s(buf, 256 * sizeof(unsigned char), "%scpa\\cpa_nonce.corrtrace", _FOLD_);

	if ((err = fopen_s(&wfp, buf, "wb"))) {
		printf("File Open Error5!!\n");
	}


	fwrite(corrT, sizeof(double), TraceLength, wfp);
	fclose(wfp);
	free(Sx);
	free(Sxx);
	free(Sxy);
	free(corrT);
	free(data);
	free(plaintext);
}
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

	int main() {

		CPA_Plain();
		return 0;
	}