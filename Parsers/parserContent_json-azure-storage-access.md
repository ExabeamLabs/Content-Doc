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
    """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
    """time":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """callerIpAddress":\s*"({src_ip}[^"]+)"""",
    """clientInfo":"({user_agent}[^"]+)"""",
    """resultType":\s*"({outcome}[^"]+)"""",
    """httpStatusCode":({result_code}\d+),""",
    """category":\s*"({category}[^"]+)"""",
    """requestUri":"({full_url}(({protocol}[^:]+):\/\/)?({web_domain}[^\/:\s]+)({uri_path}\/[^\?"]+)?(\?({uri_query}[^"]+))?)""",
    """operationName":\s*"({activity}[^"]+)"""
  ]
}
```