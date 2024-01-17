### How to upload stuff to splunk

Need to have `:8089` exposed in order to connect to the api

Curl command:
```sh
curl -D - -u tobias:[redacted] -F 'data=@test.evtx' "https://145.100.105.146:8089/services/receivers/stream?sourcetype=preprocess-winevt&index=main&host=curl-testing2" --insecure
HTTP/1.1 100 Continue

HTTP/1.1 204 No Content
Date: Wed, 17 Jan 2024 14:11:48 GMT
Expires: Thu, 26 Oct 1978 00:00:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
Content-Length: 0
Vary: Cookie, Authorization
Connection: Keep-Alive
X-Frame-Options: SAMEORIGIN
Server: Splunkd

```



**Sources:**
- https://www.cloud-response.com/2019/07/importing-windows-event-log-files-into.html
- https://michael-gale.medium.com/upload-files-into-splunk-through-the-api-6aa9ca912545

