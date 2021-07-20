#### Parser Content
```Java
{
Name = s-owa-activity
    Vendor = Microsoft
    Product = Exchange
    Lms = Splunk
    DataType = "app-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ "ISAWebLog", "exabeam_raw" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """exabeam_raw=.*?({time}[^\s]{1,2000})""",
      """ISAWebLog\t[^\t]{1,2000}\t({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """ISAWebLog\t([^\t]{1,2000}\t){2}\(\w+\)({user}.+?)\t""",
      """ISAWebLog\t([^\t]{1,2000}\t){6}(?:-|({app}.+?))\t""",
      """ISAWebLog\t([^\t]{1,2000}\t){12}(?:-|({activity}.+?))\t""",
      """Cmd=({activity}.+?)(\t|&)""",
      """ISAWebLog\t([^\t]{1,2000}\t){7}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """ISAWebLog\t([^\t]{1,2000}\t){13}(?:-|({additional_info}.+?))\t""",
      """DeviceType=({src_host}[^&\t]{1,2000})"""
      """User=({domain}[^%]{1,2000})%5C"""
    ]
  }
```