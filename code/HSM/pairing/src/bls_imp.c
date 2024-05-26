#include <stdio.h>
#include <stdlib.h>
#include <jni.h>
#include "relic.h"
#include "bls_BLS.h"

int t;

bn_t order;
bn_t fermat_exp;

void throw_illegal_state_exception(JNIEnv *env, char *message) {
	char *className = "java/lang/IllegalStateException";
	jclass exClass = (*env)->FindClass(env, className);
	(*env)->ThrowNew(env, exClass, message);
}

bn_t *convert_bytes_to_bn(JNIEnv *env, jbyteArray bytes) {
	jsize bin_size = (*env)->GetArrayLength(env, bytes);
	jbyte* bin = malloc(sizeof(jbyte) * bin_size);
	(*env)->GetByteArrayRegion(env, bytes, 0, bin_size, bin);
	bn_t *result = malloc(sizeof(bn_t));
	bn_null(*result);
	bn_new(*result);
	bn_read_bin(*result, bin, bin_size);

	free(bin);
	return result;
}

jbyteArray convert_bn_to_bytes(JNIEnv *env, bn_t* num) {
    int nBytes = bn_size_bin(*num);
    uint8_t* bytes = malloc(sizeof(uint8_t) * nBytes);
    bn_write_bin(bytes, nBytes, *num);

    jbyteArray result = (*env)->NewByteArray(env, nBytes);
    (*env)->SetByteArrayRegion(env, result, 0, nBytes, bytes);
    free(bytes);
    return result;
}

jbyteArray convert_g2_to_bytes(JNIEnv *env, g2_t* num) {
    int nBytes = g2_size_bin(*num, 1);
    uint8_t* bytes = malloc(sizeof(uint8_t) * nBytes);
    g2_write_bin(bytes, nBytes, *num, 1);

    jbyteArray result = (*env)->NewByteArray(env, nBytes);
    (*env)->SetByteArrayRegion(env, result, 0, nBytes, bytes);
    free(bytes);
    return result;
}

jbyteArray convert_g1_to_bytes(JNIEnv *env, g1_t* num) {
    int nBytes = g1_size_bin(*num, 1);
    uint8_t* bytes = malloc(sizeof(uint8_t) * nBytes);
    g1_write_bin(bytes, nBytes, *num, 1);

    jbyteArray result = (*env)->NewByteArray(env, nBytes);
    (*env)->SetByteArrayRegion(env, result, 0, nBytes, bytes);
    free(bytes);
    return result;
}

g1_t *convert_bytes_to_g1(JNIEnv *env, jbyteArray bytes) {
	int bin_size = (*env)->GetArrayLength(env, bytes);
	uint8_t *bin = malloc(sizeof(uint8_t) * bin_size);
	(*env)->GetByteArrayRegion(env, bytes, 0, bin_size, bin);
	g1_t *result = malloc(sizeof(g1_t));
	g1_null(*result);
	g1_new(*result);
	g1_read_bin(*result, bin, bin_size);
	free(bin);
	return result;
}

g2_t *convert_bytes_to_g2(JNIEnv *env, jbyteArray bytes) {
	int bin_size = (*env)->GetArrayLength(env, bytes);
	uint8_t *bin = malloc(sizeof(uint8_t) * bin_size);
	(*env)->GetByteArrayRegion(env, bytes, 0, bin_size, bin);
	g2_t *result = malloc(sizeof(g2_t));
	g2_null(*result);
	g2_new(*result);
	g2_read_bin(*result, bin, bin_size);
	free(bin);
	return result;
}

bn_t *bn_custom_invert(bn_t number) {
	bn_t *result = malloc(sizeof(bn_t));
	bn_null(*result);
	bn_new(*result);
	bn_mxp_slide(*result, number, fermat_exp, order);
	return result;
}

bn_t *multiply_polynomials(bn_t *values_1, bn_t *values_2, int n_values_1, int n_values_2) {
	int len = n_values_1 + n_values_2 - 1;
	bn_t *result = malloc(sizeof(bn_t) * len);
	for(int i = 0; i < len; i++) {
		bn_new(result[i]);
		bn_null(result[i]);
		bn_zero(result[i]);
	}

	bn_t temp;
	bn_null(temp);
	bn_new(temp);

	for (int i = 0; i < n_values_1; i++) {
		for (int j = 0; j < n_values_2; j++) {
			bn_mul_karat(temp, values_1[i], values_2[j]);
			bn_add(result[i + j], result[i + j], temp);
			bn_mod_basic(result[i + j], result[i + j], order);
		}
	}

	return result;
}

/*
* len_1 >= len_2
*/
void add_polynomials_g1(g1_t *polynomial_1, g1_t *polynomial_2, int len_1, int len_2) {
	for (int i = len_1 - 1, j = len_2 - 1; j >= 0; i--, j--) {
		g1_add(polynomial_1[i], polynomial_1[i], polynomial_2[j]);
	}
}

/*
* len_1 >= len_2
*/
void add_polynomials_g2(g2_t *polynomial_1, g2_t *polynomial_2, int len_1, int len_2) {
	for (int i = len_1 - 1, j = len_2 - 1; j >= 0; i--, j--) {
		g2_add(polynomial_1[i], polynomial_1[i], polynomial_2[j]);
	}
}

int compute_polynomial_degree_g1(g1_t *polynomial, int len) {
	int degree = len - 1;
	for (int i = 0; i < len; i++)
	{
		if (g1_is_infty(polynomial[i]) == 0)
			return degree;
		degree--;
	}

	return degree;
}

int compute_polynomial_degree_g2(g2_t *polynomial, int len) {
	int degree = len - 1;
	for (int i = 0; i < len; i++)
	{
		if (g2_is_infty(polynomial[i]) == 0)
			return degree;
		degree--;
	}

	return degree;
}

g1_t *evaluate_polynomial_at_g1(bn_t x, g1_t *polynomial, int degree) {
	g1_t *result = malloc(sizeof(g1_t));
	g1_null(*result);
	g1_new(*result);
	g1_copy(*result, polynomial[0]);

	for (int i = 1; i < degree; i++) {
		g1_mul_key(*result, *result, x);
		g1_add(*result, polynomial[i], *result);
	}

	return result;
}

g2_t *evaluate_polynomial_at_g2(bn_t x, g2_t *polynomial, int degree) {
	g2_t *result = malloc(sizeof(g2_t));
	g2_null(*result);
	g2_new(*result);
	g2_copy(*result, polynomial[0]);

	for (int i = 1; i < degree; i++) {
		g2_mul(*result, *result, x);
		g2_add(*result, polynomial[i], *result);
	}

	return result;
}

bn_t** compute_lagrange_polynomials(bn_t *xs[], int n_points) {
	bn_t denominator, temp;
	bn_null(denominator);
	bn_null(temp);
	bn_new(denominator);
	bn_new(temp);
	bn_t **lagrange_polynomials = malloc(sizeof(bn_t*) * n_points);

	for (int i = 0; i < n_points; i++) {
		bn_read_str(denominator, "1", 1, 2);
		bn_t *numerator = NULL;
		int numerator_size = 1;
		for (int m = 0; m < n_points; m++) {
			if (i == m)
				continue;
			bn_t *current_numerator = malloc(sizeof(bn_t) * 2);
			bn_null(current_numerator[0]);
			bn_null(current_numerator[1]);
			bn_new(current_numerator[0]);
			bn_new(current_numerator[1]);
			bn_read_str(current_numerator[0], "1", 1, 2);
			bn_copy(current_numerator[1], *xs[m]);
			bn_neg(current_numerator[1], current_numerator[1]);
			if (numerator == NULL) {
				numerator = current_numerator;
				numerator_size = 2;
			} else {
				numerator = multiply_polynomials(numerator, current_numerator, numerator_size, 2);
				numerator_size = numerator_size + 1;
				free(current_numerator);
			}


			bn_sub(temp, *xs[i], *xs[m]);
			bn_mul_karat(denominator, denominator, temp);
			bn_mod_basic(denominator, denominator, order);
		}

		bn_t *d_inverted = bn_custom_invert(denominator);
		numerator = multiply_polynomials(numerator, d_inverted, numerator_size, 1);
		free(d_inverted);

		lagrange_polynomials[i] = numerator;
	}

	return lagrange_polynomials;
}

g1_t* g1_interpolate_and_evaluate_at(bn_t x, bn_t *xs[], g1_t *ys[], int n_points) {
	bn_t** lagrange_polynomials = compute_lagrange_polynomials(xs, n_points);

	g1_t *polynomial = NULL;
	for (int i = 0; i < n_points; i++) {
		bn_t *numerator = lagrange_polynomials[i];
		g1_t *li = malloc(sizeof(g1_t) * n_points);
		for (int j = 0; j < n_points; j++) {
			g1_mul_key(li[j], *ys[i], numerator[j]);
		}

		free(numerator);

		if (polynomial == NULL) {
			polynomial = li;
		} else {
			add_polynomials_g1(polynomial, li, n_points, n_points);
		}
	}
	free(lagrange_polynomials);
	int degree = compute_polynomial_degree_g1(polynomial, n_points);
	if (degree != t) {
		free(polynomial);
    	return NULL;
    }
	g1_t *independent_term = evaluate_polynomial_at_g1(x, polynomial, n_points);
	free(polynomial);
	return independent_term;
}

g2_t* g2_interpolate_and_evaluate_at(bn_t x, bn_t *xs[], g2_t *ys[], int n_points) {
	bn_t** lagrange_polynomials = compute_lagrange_polynomials(xs, n_points);

	g2_t *polynomial = NULL;
	for (int i = 0; i < n_points; i++) {
		bn_t *numerator = lagrange_polynomials[i];
		g2_t *li = malloc(sizeof(g2_t) * n_points);
		for (int j = 0; j < n_points; j++) {
			g2_mul(li[j], *ys[i], numerator[j]);
		}

		free(numerator);

		if (polynomial == NULL) {
			polynomial = li;
		} else {
			add_polynomials_g2(polynomial, li, n_points, n_points);
		}
	}
	free(lagrange_polynomials);
	int degree = compute_polynomial_degree_g2(polynomial, n_points);
	if (degree != t) {
    	free(polynomial);
       	return NULL;
    }
	g2_t *independent_term = evaluate_polynomial_at_g2(x, polynomial, n_points);
    free(polynomial);
	return independent_term;
}

g1_t *interpolatePartialSignatures(bn_t x, bn_t *xs[], g1_t *ys[], int n_points) {
	if (n_points == 1)
		return ys[0];

	bn_t denominator, numerator, temp;
	bn_null(denominator);
	bn_null(numerator);
	bn_null(temp);
	bn_new(denominator);
	bn_new(numerator);
	bn_new(temp);
	g1_t *result = malloc(sizeof(g1_t));

	g1_null(*result);
	g1_new(*result);

	for (int i = 0; i < n_points; i++) {
		bn_read_str(denominator, "1", 1, 2);
		bn_read_str(numerator, "1", 1, 2);
		for (int j = 0; j < n_points; j++) {
			if (i == j)
				continue;
			bn_sub(temp, x, *xs[j]);

			bn_mul_karat(numerator, numerator, temp);
			//bn_mod_basic(numerator, numerator, order);

			bn_sub(temp, *xs[i], *xs[j]);
			bn_mul_karat(denominator, denominator, temp);
			//bn_mod_basic(denominator, denominator, order);
		}
		g1_t v;
		g1_null(v);
		g1_new(v);
		bn_t quotient, rem;
		bn_null(quotient);
		bn_null(rem);
		bn_new(quotient);
		bn_new(rem);
		bn_div_rem(quotient, rem, numerator, denominator);

		g1_mul_key(v, *ys[i], quotient);
		if (i == 0)
			g1_copy(*result, v);
		else
			g1_add(*result, *result, v);
	}
	return result;
}

g2_t *interpolatePartialPublicKeys(bn_t x, bn_t *xs[], g2_t *ys[], int n_points) {
	if (n_points == 1)
		return ys[0];

	bn_t denominator, numerator, temp;
	bn_null(denominator);
	bn_null(numerator);
	bn_null(temp);
	bn_new(denominator);
	bn_new(numerator);
	bn_new(temp);
	g2_t *result = malloc(sizeof(g2_t));

	g2_null(*result);
	g2_new(*result);

	for (int i = 0; i < n_points; i++) {
		bn_read_str(denominator, "1", 1, 2);
		bn_read_str(numerator, "1", 1, 2);
		for (int j = 0; j < n_points; j++) {
			if (i == j)
				continue;
			bn_sub(temp, x, *xs[j]);

			bn_mul_karat(numerator, numerator, temp);
			//bn_mod_basic(numerator, numerator, order);

			bn_sub(temp, *xs[i], *xs[j]);
			bn_mul_karat(denominator, denominator, temp);
			//bn_mod_basic(denominator, denominator, order);
		}
		g2_t v;
		g2_null(v);
		g2_new(v);
		bn_t quotient, rem;
		bn_null(quotient);
		bn_null(rem);
		bn_new(quotient);
		bn_new(rem);
		bn_div_rem(quotient, rem, numerator, denominator);

		g2_mul(v, *ys[i], quotient);
		if (i == 0)
			g2_copy(*result, v);
		else
			g2_add(*result, *result, v);
	}
	return result;
}

JNIEXPORT void JNICALL Java_bls_BLS_initialize(JNIEnv *env, jobject obj, jint threshold) {
	t = threshold;

    core_init();
	ep_param_set_any_pairf();

	ep_param_print();

	int embed = ep_param_embed();
	printf("\n-- Embed: %d\n", embed);

	bn_null(order);
	bn_new(order);
	ep_curve_get_ord(order);

	bn_t TWO;
	bn_null(TWO);
	bn_new(TWO);
	bn_read_str(TWO, "2", 1, 10);

	bn_null(fermat_exp);
	bn_new(fermat_exp);
	bn_sub(fermat_exp, order, TWO);
}

JNIEXPORT jobjectArray JNICALL Java_bls_BLS_computeKeyPair(JNIEnv *env, jobject obj) {
    bn_t* private_key = malloc(sizeof(bn_t));
    g2_t* public_key = malloc(sizeof(g2_t));
    bn_null(*private_key);
    g2_null(*public_key);
    bn_new(*private_key);
    g2_new(*public_key);

    cp_bls_gen(*private_key, *public_key);

	jbyteArray private_key_bytes = convert_bn_to_bytes(env, private_key);
	jbyteArray public_key_bytes = convert_g2_to_bytes(env, public_key);

	jobjectArray result = (*env)->NewObjectArray(env, 2, (*env)->FindClass(env, "[B"), (*env)->NewByteArray(env, 1));
	(*env)->SetObjectArrayElement(env, result, 0, private_key_bytes);
	(*env)->SetObjectArrayElement(env, result, 1, public_key_bytes);

    free(private_key);
    free(public_key);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_bls_BLS_computePublicKey(JNIEnv *env, jobject obj, jbyteArray private_key_bytes) {
	bn_t *private_key = convert_bytes_to_bn(env, private_key_bytes);
	g2_t* public_key = malloc(sizeof(g2_t));
	g2_null(*public_key);
	g2_new(*public_key);

	g2_mul_gen(*public_key, *private_key);
	jbyteArray public_key_bytes = convert_g2_to_bytes(env, public_key);

	free(public_key);
	free(private_key);
	return public_key_bytes;
}

JNIEXPORT jbyteArray JNICALL Java_bls_BLS_getOrderBytes(JNIEnv *env, jobject obj) {
    int nBytes = bn_size_bin(order);
    uint8_t* bytes = malloc(sizeof(uint8_t) * nBytes);
    bn_write_bin(bytes, nBytes, order);

    jbyteArray result = (*env)->NewByteArray(env, nBytes);
    (*env)->SetByteArrayRegion(env, result, 0, nBytes, bytes);
    free(bytes);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_bls_BLS_computeSignature(JNIEnv *env, jobject obj, jbyteArray private_key_bytes,
	jbyteArray message) {
    bn_t *private_key = convert_bytes_to_bn(env, private_key_bytes);

    int msg_size = (*env)->GetArrayLength(env, message);
    uint8_t* msg = malloc(sizeof(uint8_t) * msg_size);
    (*env)->GetByteArrayRegion(env, message, 0, msg_size, msg);

    g1_t* signature = malloc(sizeof(g1_t));
    g1_null(signature);
    g1_new(signature);

    cp_bls_sig(*signature, msg, msg_size, *private_key);

    jbyteArray result = convert_g1_to_bytes(env, signature);

    free(private_key);
    free(msg);
    free(signature);
    return result;
}

JNIEXPORT jboolean JNICALL Java_bls_BLS_computeVerification(JNIEnv *env, jobject obj,
	jbyteArray signature, jbyteArray message, jbyteArray public_key) {

	g1_t *signature_point = convert_bytes_to_g1(env, signature);

	int msg_size = (*env)->GetArrayLength(env, message);
	uint8_t* msg = malloc(sizeof(uint8_t) * msg_size);
	(*env)->GetByteArrayRegion(env, message, 0, msg_size, msg);

	g2_t *public_key_point = convert_bytes_to_g2(env, public_key);

	int is_valid = cp_bls_ver(*signature_point, msg, msg_size, *public_key_point);

	free(public_key_point);
	free(msg);
	free(signature_point);
	return is_valid;
}

JNIEXPORT jbyteArray JNICALL Java_bls_BLS_interpolatePartialSignatures(JNIEnv *env, jobject obj,
	jobjectArray partial_signatures_bytes) {
	int n_partial_signatures = (*env)->GetArrayLength(env, partial_signatures_bytes);

	bn_t *xs[n_partial_signatures];
	g1_t *ys[n_partial_signatures];

	for (int i = 0; i < n_partial_signatures; i++) {
		jobjectArray partial_signature_bytes = (*env)->GetObjectArrayElement(env, partial_signatures_bytes, i);
		jbyteArray x_value_bytes = (*env)->GetObjectArrayElement(env, partial_signature_bytes, 0);
        jbyteArray y_value_bytes = (*env)->GetObjectArrayElement(env, partial_signature_bytes, 1);

        bn_t *x_value = convert_bytes_to_bn(env, x_value_bytes);
        g1_t *y_value = convert_bytes_to_g1(env, y_value_bytes);

        xs[i] = x_value;
        ys[i] = y_value;
	}

	bn_t x;
	bn_null(x);
	bn_new(x);
	bn_read_str(x, "0", 1, 2);
	g1_t *combinedSignature = g1_interpolate_and_evaluate_at(x, xs, ys, n_partial_signatures);
	//g1_t *combinedSignature = interpolatePartialSignatures(x, xs, ys, n_partial_signatures);
	if (combinedSignature == NULL) {
		throw_illegal_state_exception(env, "Partial signatures polynomial degree is incorrect");
		return NULL;
	}
	jbyteArray result = convert_g1_to_bytes(env, combinedSignature);

	free(combinedSignature);

	return result;
}

JNIEXPORT jbyteArray JNICALL Java_bls_BLS_interpolatePartialPublicKeys(JNIEnv *env, jobject obj,
	jobjectArray partial_keys_bytes) {
	int n_partial_keys = (*env)->GetArrayLength(env, partial_keys_bytes);
	bn_t *xs[n_partial_keys];
	g2_t *ys[n_partial_keys];

	for (int i = 0; i < n_partial_keys; i++) {
		jobjectArray partial_key_bytes = (*env)->GetObjectArrayElement(env, partial_keys_bytes, i);
		jbyteArray x_value_bytes = (*env)->GetObjectArrayElement(env, partial_key_bytes, 0);
		jbyteArray y_value_bytes = (*env)->GetObjectArrayElement(env, partial_key_bytes, 1);

		bn_t *x_value = convert_bytes_to_bn(env, x_value_bytes);
		g2_t *y_value = convert_bytes_to_g2(env, y_value_bytes);

		xs[i] = x_value;
		ys[i] = y_value;
	}
	bn_t x;
	bn_null(x);
	bn_new(x);
	bn_read_str(x, "0", 1, 2);

	g2_t *combinedKey = g2_interpolate_and_evaluate_at(x, xs, ys, n_partial_keys);
	//g2_t *combinedKey = interpolatePartialPublicKeys(x, xs, ys, n_partial_keys);
	if (combinedKey == NULL) {
		throw_illegal_state_exception(env, "Partial public keys polynomial degree is incorrect");
		return NULL;
	}
	jbyteArray result = convert_g2_to_bytes(env, combinedKey);

	free(combinedKey);

	return result;
}