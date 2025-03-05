#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "crypto_aead.h"
#include "api.h"

#define _FOLD_ "C:\\Users\\ATIV\\Desktop\\aesÆÄÇü\\"
#define TraceFN "2022.03.12-04.08.12_traces.npy"
#define AlignedTraceFN "AlignedTrace.traces"
#define startpoint 0
#define endpoint 24000

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

#define MESSAGE_LENGTH			32
#define ASSOCIATED_DATA_LENGTH	32

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
	int err, TraceLength, TraceNum;
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

	fread(&TraceLength, sizeof(int), 1, rfp);
	fwrite(&TraceLength, sizeof(int), 1, wfp);

	fread(&TraceNum, sizeof(int), 1, rfp);
	fwrite(&TraceNum, sizeof(int), 1, wfp);

	data = (double*)calloc(TraceLength, sizeof(double));
	data1 = (double*)calloc(TraceLength, sizeof(double));

	fread(data, sizeof(double), TraceLength, rfp);
	fwrite(data, sizeof(double), TraceLength, wfp);

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

void init_buffer(unsigned char* buffer, unsigned long long numbytes)
{
	for (unsigned long long i = 0; i < numbytes; i++)
		buffer[i] = (unsigned char)i;
}

void CPA() {
	double** data;
	double* Sx, * Sxx, * Sxy, * corrT;
	double Sy, Syy, max;
	unsigned char temp[34], x, y, iv, hw_iv;
	char buf[256];
	int err, TraceLength = 24000, TraceNum = 5000, i, j, k, key_a, maxkey;
	FILE* rfp, * wfp;

	sprintf_s(buf, 256 * sizeof(char), "%s%s", _FOLD_, AlignedTraceFN);
	if ((err = fopen_s(&rfp, buf, "rb"))) {
		printf("File Open Error!!\n");
		exit(1);
	}


	data = (float**)calloc(TraceNum, sizeof(double*));

	for (i = 0; i < TraceNum; i++) {
		data[i] = (double*)calloc(TraceLength, sizeof(double));
	}
	for (i = 0; i < TraceNum; i++) {
		fread(data[i], sizeof(double), TraceLength, rfp);
	}

	fclose(rfp);

	unsigned char       key[CRYPTO_KEYBYTES];
	unsigned char		nonce[CRYPTO_NPUBBYTES];
	unsigned char       msg[MESSAGE_LENGTH];
	unsigned char       msg2[MESSAGE_LENGTH];
	unsigned char		ad[ASSOCIATED_DATA_LENGTH];
	unsigned char		ct[MESSAGE_LENGTH + CRYPTO_ABYTES];
	unsigned long long	clen, mlen2;
	int                 count = 1;
	int                 func_ret, ret_val = KAT_SUCCESS;

	init_buffer(key, sizeof(key));
	init_buffer(nonce, sizeof(nonce));
	init_buffer(msg, sizeof(msg));
	init_buffer(ad, sizeof(ad));

	unsigned long long mlen = MESSAGE_LENGTH;
	unsigned long long adlen = ASSOCIATED_DATA_LENGTH;

	isap_enc(k, nonce, msg, mlen, ct);
	state_t state;
	state_t* s = &state;

	// Initialize
	s->l[0] = U64TOWORD(*(lane_t*)(nonce + 0));
	s->l[1] = U64TOWORD(*(lane_t*)(nonce + 8));
	s->l[2] = U64TOWORD(*(lane_t*)(ISAP_IV_A + 0));
	s->x[3] = 0;
	s->x[4] = 0;
	P_sH;

	// Absorb associated data
	ABSORB_LANES(s, ad, adlen);

	// Domain seperation
	s->w[4][0] ^= 0x1UL;

	// Absorb ciphertext
	ABSORB_LANES(s, ct, clen);

	// Derive KA*
	s->l[0] = WORDTOU64(s->l[0]);
	s->l[1] = WORDTOU64(s->l[1]);


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

	for (i = 0; i < 1; i++) {
		max = 0;
		maxkey = 0;
		for (key_a = 0; key_a < 2 ; key_a++) {
			Sy = 0;
			Syy = 0;
			memset(Sxy, 0, sizeof(double) * TraceLength);
			for (j = 0; j < TraceNum; j++) {
				iv = s[0][0] ^ key_a; //------------------------------------------
				hw_iv = 0;
				for (k = 0; k < 8; k++) {
					hw_iv += ((iv >> k) & 1);
				}
				Sy += hw_iv;
				Syy += hw_iv * hw_iv;
				for (k = startpoint; k < endpoint; k++) {
					Sxy[k] += hw_iv * data[j][k];
				}
			}
			for (k = startpoint; k < endpoint; k++) {
				corrT[k] = ((double)TraceNum * Sxy[k] - Sx[k] * Sy) / sqrt(((double)TraceNum * Sxx[k] - Sx[k] * Sx[k]) * ((double)TraceNum * Syy - Sy * Sy));
				if (fabs(corrT[k]) > max) {
					maxkey = key_a;
					max = fabs(corrT[k]);
				}
			}
			sprintf_s(buf, 256 * sizeof(char), "%scorrtrace\\%02dth_block_%02x.corrtrace", _FOLD_, i, key_a);
			if ((err = fopen_s(&wfp, buf, "wb"))) {
				printf("File Open Error!!\n");
				exit(1);
			}

			fwrite(corrT, sizeof(double), TraceLength, wfp);
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
}

int main() {
	CPA();
}