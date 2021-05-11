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
    """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
    """time":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """callerIpAddress":\s{0,100}"({src_ip}[^"]+)"""",
    """clientInfo":"({user_agent}[^"]+)"""",
    """resultType":\s{0,100}"({outcome}[^"]+)"""",
    """httpStatusCode":({result_code}\d{1,100}),""",
    """category":\s{0,100}"({category}[^"]+)"""",
    """requestUri":"({full_url}(({protocol}[^:]+):\/\/)?({web_domain}[^\/:\s]+)({uri_path}\/[^\?"]+)?(\?({uri_query}[^"]+))?)""",
    """operationName":\s{0,100}"({activity}[^"]+)"""
  ]
}
```