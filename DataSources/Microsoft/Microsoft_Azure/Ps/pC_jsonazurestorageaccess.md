#### Parser Content
```Java
{
Name = json-azure-storage-access
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "cloud-storage-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""Skyformation""", """dproc=Blob Sync""" , """Application=Azure""", """"callerIpAddress":"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """time":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """callerIpAddress":\s{0,100}"({src_ip}[^"]{1,2000})"""",
    """clientInfo":"({user_agent}[^"]{1,2000})"""",
    """resultType":\s{0,100}"({outcome}[^"]{1,2000})"""",
    """httpStatusCode":({result_code}\d{1,100}),""",
    """category":\s{0,100}"({category}[^"]{1,2000})"""",
    """requestUri":"({full_url}(({protocol}[^:]{1,2000}):\/\/)?({web_domain}[^\/:\s]{1,2000})({uri_path}\/[^\?"]{1,2000})?(\?({uri_query}[^"]{1,2000}))?)""",
    """operationName":\s{0,100}"({activity}[^"]{1,2000})"""
  ]


}
```