#ifndef S1AP_STRUCTURED_H
#define S1AP_STRUCTURED_H

#ifdef __cplusplus
extern "C" {
#endif

struct structured_output {
    char *buffer_ptr;
    long buffer_len;
};

const long INITIATING_MESSAGE = 1 << 8;
const long SUCCESSFUL_OUTCOME = 2 << 8;
const long UNSUCCESSFUL_OUTCOME = 3 << 8;


// Converts arbitrary unstructured bytes into a structured S1AP message.
// Returns a the number of structured output buffers written to in `out`, or
// a negative error code on failure. Note that a maximum of 6 buffers may
// be written to.
//long s1ap_arbitrary_to_multistructured(char *buf_in, long in_len, struct structured_output *out, long out_len);


// Converts arbitrary unstructured bytes into a structured S1AP message.
// Returns a the length of the structured bytes written to `buf_out`, or
// a negative error code on failure.
long s1ap_arbitrary_to_structured(char *buf_in, long in_len, char *buf_out, long out_max);

// Converts arbitrary unstructured bytes into a structured S1AP message,
// excluding the given PDU message types.
// Returns a the length of the structured bytes written to `buf_out`, or
// a negative error code on failure (or if the structured message would
// have been one of the excluded types).
long s1ap_arbitrary_to_structured_exclude(char *buf_in, long in_len, long *pdus, long pdus_len, char *buf_out, long out_max);

// Determines the length of the message in the given buffer.
// Useful for determining if multiple messages are in a buffer.
// Returns a negative value on failure.
long s1ap_msg_len(char *buf_in, long in_len);

// Derives a unique response code from the given S1AP message.
// Returns 0 if `in_len` is less than 0, or if the S1AP message could not be parsed.
// Note that this method can also return a unique request code from a given S1AP message.
unsigned int s1ap_response_code(char *buf_in, long in_len);

#ifdef __cplusplus
}
#endif

#endif
