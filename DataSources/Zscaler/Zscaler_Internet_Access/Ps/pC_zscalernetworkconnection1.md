#### Parser Content
```Java
{
Name = zscaler-network-connection-1
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Direct
  DataType = "network-connection"
  TimeFormat= "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|Zscaler|NSSFWlog|""", """ reason=""", """ act=""", """ suser="""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """suser=(({user_email}[^=@]{1,2000}@[^\.\s]{1,2000}\.[^=]{1,2000}?)|({user}[^=]{1,2000}?))\s{1,100}\w+=""",
    """src=({src_ip}[A-Fa-f\d:.]{1,2000})""",
    """dst=({dest_ip}[A-Fa-f\d:.]{1,2000})""",
    """spt=({src_port}\d{1,100})""",
    """dpt=({dest_port}\d{1,100})""",
    """(?i)\sact=({action}(Allow|Drop))""",
    """sourceTranslatedAddress=({src_translated_ip}[A-Fa-f:.\d]{1,2000})""",
    """destinationTranslatedAddress=({dest_translated_ip}[A-Fa-f:.\d]{1,2000})""",
    """proto=({protocol}[^=]{1,2000}?)\s\w+=""",
    """deviceDirection=({direction}\d)""",
    """reason=({rule}[^=]{1,2000}?)\s{1,100}\w+=""",
    """in=({bytes_in}\d{1,100})""",
    """out=({bytes_out}\d{1,100})"""
    ]


}
```