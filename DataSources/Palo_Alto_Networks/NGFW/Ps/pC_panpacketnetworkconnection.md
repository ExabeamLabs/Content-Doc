#### Parser Content
```Java
{
Name = pan-packet-network-connection
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,packet,""", """,client""", """,,""" ]
  Fields = [
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\d{1,100}
```