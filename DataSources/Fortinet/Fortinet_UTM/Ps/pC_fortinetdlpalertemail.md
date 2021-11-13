#### Parser Content
```Java
{
Name = fortinet-dlp-alert-email
  Vendor = Fortinet
  Product = Fortinet UTM
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd' time='HH:mm:ss"
  Conditions = [ """subtype=dlp""", """service=SMTP""" ]
  Fields = [
    """\Wdate=({time}\d\d\d\d-\d\d-\d\d time\=\d\d:\d\d:\d\d)""",
    """\Wdevname="{0,20}({host}[^\s"]{1,2000})"{0,20}(\s|")""",
    """\Wsubtype="({alert_type}[^"]{1,2000})"""",
    """\Waction=({action}.+?)\s{1,100}\w+=""",
    """\Wsrcip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdstip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wrcvdbyte=({bytes_in}\d{1,100})"""
    """\Wsentbyte=({bytes_out}\d{1,100})"""
    """\Wsrcport=({src_port}\d{1,100})"""
    """\Wdstport=({dest_port}\d{1,100})"""
    """\Wseverity=({alert_severity}.*?)\s{1,100}\w+="""
    """\Wfiltercat="{0,20}(none|({category}.*?))"{0,20}\s{1,100}\w+="""
    """\Wfrom="\(*({sender}.*?@.*?)\)*"\s{1,100}\w+="""
    """\Wfilesize=({file_size}\d{1,100})\s{1,100}\w+="""
    """\Wfilename="({attachments}.*?)"\s{1,100}\w+="""
    """\Wrecipient="({recipient}.*?@.*?)"\s{1,100}\w+="""
    """\Wsubject="\s{0,100}({subject}.*?)\s{0,100}"\s{1,100}\w+="""
    """\Weventtype=({alert_type}[^\s]{1,2000}?)\s{1,100}\w+="""
    """\Wsubtype=({alert_name}[^\s]{1,2000}?)\s{1,100}\w+="""
    """\Wsessionid=({alert_id}\d{1,100})"""
  ]
  DupFields = ["bytes_out->bytes", "recipient->recipients"]


}
```