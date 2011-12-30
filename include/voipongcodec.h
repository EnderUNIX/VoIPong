#ifndef VOIPONGCODEC_H_
#define VOIPONGCODEC_H_

#define	MAXCODECS	128

typedef	int	vocoder_t(int, unsigned char *, int);

typedef struct vocoder vocoder;
struct vocoder {
	int rate;
	vocoder_t *f;
};

void init_vocoders(void);
int vocoder_default(int, unsigned char *, int);

#endif
