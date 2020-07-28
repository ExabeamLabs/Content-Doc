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
    """\Wdevname="*({host}[^\s"]+)"*(\s|")""",
    """\Wsubtype="({alert_type}[^"]+)"""",
    """\Waction=({action}.+?)\s+\w+=""",
    """\Wsrcip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdstip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wrcvdbyte=({bytes_in}\d+)"""
    """\Wsentbyte=({bytes_out}\d+)"""
    """\Wsrcport=({src_port}\d+)"""
    """\Wdstport=({dest_port}\d+)"""
    """\Wseverity=({alert_severity}.*?)\s+\w+="""
    """\Wfiltercat="*(none|({category}.*?))"*\s+\w+="""
    """\Wfrom="\(*({sender}.*?@({external_domain_sender}.*?))\)*"\s+\w+="""
    """\Wfilesize=({file_size}\d+)\s+\w+="""
    """\Wfilename="({attachments}.*?)"\s+\w+="""
    """\Wrecipient="({recipient}.*?@({external_domain_recipient}.*?))"\s+\w+="""
    """\Wsubject="\s*({subject}.*?)\s*"\s+\w+="""
    """\Weventtype=({alert_type}[^\s]+?)\s+\w+="""
    """\Wsubtype=({alert_name}[^\s]+?)\s+\w+="""
    """\Wsessionid=({alert_id}\d+)"""
  ]
  DupFields = ["bytes_out->bytes", "recipient->recipients"]
}
```