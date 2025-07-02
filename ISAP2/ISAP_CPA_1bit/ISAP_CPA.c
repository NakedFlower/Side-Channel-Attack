#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "api.h"
#include "asconp.h"
#include "config.h"

#define _FOLD_ "D:\\Isap\\"
#define TraceFN "2022.08.17-08.52.47_traces.npy"
#define AlignedTraceFN "AlignedTrace.traces"
#define PlaintextFN "2022.08.17-08.52.47_textin.npy"
#define CiphertextFN "ciphertext.txt"
#define startpoint 0
#define endpoint 12000

int sbox[32] = { 0x04, 0x0b, 0x1f, 0x14, 0x1a, 0x15, 0x09, 0x02, 0x1b,0x05, 0x08, 0x12, 0x1d, 0x03, 0x06, 0x1c,
				0x1e, 0x13,	0x07, 0x0e, 0x00, 0x0d, 0x11, 0x18,	0x10, 0x0c, 0x01, 0x19, 0x16, 0x0a, 0x0f, 0x17 };

double cov(double* x, double* y, int size) {
	double Sxy = 0, Sx = 0, Sy = 0;
	int i;

	for (i = 0; i < size; i++) {
		Sxy += (double)x[i] * y[i];
		Sx += x[i];
		Sy += y[i];
	}

	return (Sxy - Sx * Sy / (double)size) / (double)size;
}

double corr(double* x, double* y, int size) {
	double Sxy = 0, Sx = 0, Sy = 0, Sxx = 0, Syy = 0;
	int i;

	for (i = 0; i < size; i++) {
		Sxy += (double)x[i] * y[i];
		Sx += x[i];
		Sy += y[i];
		Sxx += (double)x[i] * x[i];
		Syy += (double)y[i] * y[i];
	}

	return ((double)size * Sxy - Sx * Sy) / sqrt(((double)size * Sxx - Sx * Sx) * ((double)size * Syy - Sy * Sy));
}

void subalign(double* data1, double* data2, int windowsize, int stepsize, int threshold, int TraceLength) {
	int m, j, size, maxcovpos, k;
	double* x, * y;
	double covval, maxcov;

	for (m = 0; m < TraceLength - windowsize; m += stepsize) {

		maxcovpos = 0;
		maxcov = 0;

		for (j = -threshold; j < threshold; j++) {

			if (j < 0) {
				x = data1 + m;
				y = data2 + m - j;
				size = windowsize + j;
			}
			else {
				x = data1 + m + j;
				y = data2 + m;
				size = windowsize - j;
			}

			covval = cov(x, y, size);

			if (covval > maxcov) {
				maxcovpos = j;
				maxcov = covval;
			}
		}
		if (maxcovpos < 0) {
			for (k = m; k < (TraceLength + maxcovpos); k++) {
				data2[k] = data2[k - maxcovpos];
			}
		}
		else {
			for ((k = TraceLength - maxcovpos - 1); k >= m; k--) {
				data2[k + maxcovpos] = data2[k];
			}
		}
	}
}

void Alignment() {
	int windowsize = 500;
	int stepsize = 450;
	int threshold = 100;
	char buf[256];
	int err, TraceLength = 12000, TraceNum = 10000;
	FILE* rfp, * wfp;
	double* data, * data1;

	sprintf_s(buf, 256 * sizeof(char), "%s%s", _FOLD_, TraceFN);
	if ((err = fopen_s(&rfp, buf, "rb"))) {
		printf("File Open Error!!\n");
		exit(1);
	}

	sprintf_s(buf, 256 * sizeof(char), "%s%s", _FOLD_, AlignedTraceFN);
	if ((err = fopen_s(&wfp, buf, "wb"))) {
		printf("File Open Error!!\n");
		exit(1);
	}

	data = (double*)calloc(TraceLength, sizeof(double));
	data1 = (double*)calloc(TraceLength, sizeof(double));

	fread(data, sizeof(double), TraceLength, rfp);
	fwrite(data, sizeof(double), TraceLength, wfp);

	for (int i = 1; i < TraceNum; i++) {
		fread(data1, sizeof(double), TraceLength, rfp);
		subalign(data, data1, windowsize, stepsize, threshold, TraceLength);
		printf(".");
		fwrite(data1, sizeof(double), TraceLength, wfp);
	}

	fclose(rfp);
	fclose(wfp);

	free(data);
	free(data1);
}

void CPA() {
	unsigned char** plaintext = NULL;
	unsigned char* nonce_y = NULL;
	double** data;
	double* Sx, * Sxx, * Sxy, * corrT;
	double Sy, Syy, max;
	unsigned char iv;
	double hw_iv;
	char buf[256];
	int err, TraceLength = 12000, TraceNum = 10000, i, j, k, key, maxkey;
	FILE* rfp, * wfp;
	int count = 0;

	sprintf_s(buf, 256 * sizeof(char), "%s%s", _FOLD_, TraceFN);		//파형 공간 생성 및 정보 할당
	if ((err = fopen_s(&rfp, buf, "rb"))) {
		printf("File Open Error!!\n");
		exit(1);
	}
	data = (double**)calloc(TraceNum, sizeof(double*));
	for (int i = 0; i < TraceNum; i++) {
		data[i] = (double*)calloc(TraceLength, sizeof(double));
	}
	for (int i = 0; i < TraceNum; i++) {
		fread(data[i], sizeof(double), TraceLength, rfp);
	}
	fclose(rfp);


	sprintf_s(buf, 256 * sizeof(char), "%s%s", _FOLD_, PlaintextFN);		//평문 공간 생성 및 정보 할당
	if ((err = fopen_s(&rfp, buf, "r")))		
	{
		printf("File Open Error2!!\n");
		exit(1);
	}
	plaintext = (unsigned char**)calloc(TraceNum, sizeof(unsigned char*));		
	for (int i = 0; i < TraceNum; i++) {
		plaintext[i] = (unsigned char*)calloc(16, sizeof(unsigned char));
	}
	for (int i = 0; i < TraceNum; i++) {
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

		nonce_y[i] = s->b[0][7];
		nonce_y[i] = (nonce_y[i] ^ 0x80) >> 7;
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

	max = 0;
	maxkey = 0;
	for (key = 0; key < 32; key++) {
		Sy = 0;
		Syy = 0;
		memset(Sxy, 0, sizeof(double) * TraceLength);
		for (j = 0; j < TraceNum; j++) {
			//nonce(known) ^ unknown
			iv = (nonce_y[j] * 16) ^ key;
			//상수 연산 후 Sbox
			iv = sbox[iv];
			hw_iv = (iv >> 4) & 0x01;

			Sy += hw_iv;

			Syy += hw_iv * hw_iv;
			for (k = startpoint; k < endpoint; k++) {
				Sxy[k] += hw_iv * data[j][k];
			}
		}
		for (k = startpoint; k < endpoint; k++) {
			corrT[k] = ((double)TraceNum * Sxy[k] - Sx[k] * Sy) / sqrt(((double)TraceNum * Sxx[k] - Sx[k] * Sx[k]) * ((double)TraceNum * Syy - Sy * Sy));
			if (fabs(corrT[k]) > max) {
				maxkey = key;
				max = fabs(corrT[k]);
			}
		}
		if (count == 0) {
			sprintf_s(buf, 256 * sizeof(char), "%scorrtrace\\isap.corrtrace", _FOLD_);
			if ((err = fopen_s(&wfp, buf, "wb"))) {
				printf("File Open Error!!\n");
				exit(1);
			}
			count += 1;
		}
		else {
			fopen_s(&wfp, buf, "a+b");
		}
		fwrite(corrT, sizeof(double), TraceLength, wfp);
		fclose(wfp);
		printf(".");
	}
	printf(" maxkey(%02x), maxcorr(%lf)\n", maxkey, max);
	free(Sx);
	free(Sxx);
	free(Sxy);
	free(corrT);
	free(data);
	free(plaintext);
}

int main() {
	//Alignment();
	CPA();
}