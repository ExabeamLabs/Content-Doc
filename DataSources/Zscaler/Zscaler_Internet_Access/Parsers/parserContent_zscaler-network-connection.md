#### Parser Content
```Java
{
Name = zscaler-network-connection
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Direct
  DataType = "network-connection"
  TimeFormat= "MM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """|Zscaler|NSSFWLog|""", """ suid=""", """ reason=""", """ act="""]
  Fields = [
    """rt=({time}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\d\d\d\d\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """suid=(({user_email}[^@]{1,2000}@[^\s]{1,2000})|({user}[^\s]{1,2000}))\s{1,100}""",
    """src=({src_ip}[A-Fa-f\d:.]{1,2000})""",
    """dst=({dest_ip}[A-Fa-f\d:.]{1,2000})""",
    """spt=({src_port}\d{1,100})""",
    """dpt=({dest_port}\d{1,100})""",
    """act=({action}\S+)""",
    """reason=({rule}[^=]{1,2000}?)\s{1,100}destination""",
    """in=({bytes_in}\d{1,100})""",
    """out=({bytes_out}\d{1,100})""",
    """cat=(Miscellaneous or Unknown|({ip_category}[^=]{1,2000}?))\s{1,100}(\w+=|$)"""
    ]
}
```