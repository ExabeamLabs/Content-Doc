#### Parser Content
```Java
{
Name = fortinet-dlp-alert-email-1
  Vendor = Fortinet
  Product = Fortinet UTM
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """from=""", """to=""", """subject=""", """message_name=""", """folder_description=""", """action=""" ]
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)\s{1,100}({host}[\w\-.]+)""",
    """\Waction=({action}[^;]+)""",
    """\Wfrom=({sender}[^\s@;]+@({external_domain_sender}[^\s@;]+))""",
    """\Wto=({recipients}({recipient}[^\s@;,]+@({external_domain_recipient}[^\s@;,]+))[^;]*)""",
    """\Wsubject=({subject}.*?);\s{1,100}(\w+=|$)""",
    """\Wmessage_name=({message_name}.*?);\s{1,100}(\w+=|$)""",
    """\Wmessage_size=({bytes}\d{1,100})""",
    """\Wfolder_description=({additional_info}.*?);\s{1,100}(\w+=|$)""",
    """\Wfilename=({file_name}[^\.]+\.({file_ext}.*?));\s{1,100}(\w+=|$)""",
    """\Wfiletype=({file_type}.*?);\s{1,100}(\w+=|$)""",
    """({direction}Outbound|Inbound)""",
    """Sent To:\s{0,100}({src_ip}[A-Fa-f:\d.]+)""",
  ]
  DupFields = [ "file_name->attachments" ]
}
```