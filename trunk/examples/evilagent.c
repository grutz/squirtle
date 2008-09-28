/* Example code to request a Type3 message response from a Squirtle session.
 * Uses libcurl
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

struct sqdata_in {
  size_t size;
  size_t len;
  char *data;
};

static size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
  struct sqdata_in *wdi = userp;

  while(wdi->len + (size * nmemb) >= wdi->size) {
    /* check for realloc failing in real code. */
    wdi->data = realloc(wdi->data, wdi->size*2);
    wdi->size*=2;
  }

  memcpy(wdi->data + wdi->len, buffer, size * nmemb);
  wdi->len+=size*nmemb;

  return size * nmemb;
}

int main()
{
    CURL *handle;
    CURLcode res;
    struct sqdata_in sqdata;

    memset(&sqdata, 0, sizeof(sqdata));

    handle = curl_easy_init();
    if(handle)
    {
        sqdata.size = 1024;
        sqdata.data = malloc(sqdata.size);
        curl_easy_setopt(handle, CURLOPT_USERPWD, "squirtle:eltriuqs");
        curl_easy_setopt(handle, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(handle, CURLOPT_URL, "http://localhost:8080/controller/allusers");
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, &sqdata);
        res = curl_easy_perform(handle);
        printf("Result: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(handle);
    } else {
        printf("Error getting CURL handle\n");
        exit(-1);
    }

    if (sqdata.len > 0) {
        /* Process the result here */
        printf("Result: %s\n\n", sqdata.data);
    } else {
        printf("No data returned\n");
    }
    free(sqdata.data);
    return 0;
}