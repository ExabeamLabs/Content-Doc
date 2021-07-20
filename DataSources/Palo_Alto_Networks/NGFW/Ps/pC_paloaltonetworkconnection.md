#### Parser Content
```Java
{
Name = paloalto-network-connection
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """,THREAT,url,"""]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """THREAT,[^,]{1,2000}
```