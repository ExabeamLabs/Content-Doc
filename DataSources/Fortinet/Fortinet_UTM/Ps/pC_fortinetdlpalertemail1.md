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
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)\s{1,100}({host}[\w\-.]{1,2000})""",
    """\Waction=({action}[^;]{1,2000})""",
    """\Wfrom=({sender}[^\s@;]{1,2000}@({external_domain_sender}[^\s@;]{1,2000}))""",
    """\Wto=({recipients}({recipient}[^\s@;,]{1,2000}@({external_domain_recipient}[^\s@;,]{1,2000}))[^;]{0,2000})""",
    """\Wsubject=({subject}.*?);\s{1,100}(\w+=|$)""",
    """\Wmessage_name=({message_name}.*?);\s{1,100}(\w+=|$)""",
    """\Wmessage_size=({bytes}\d{1,100})""",
    """\Wfolder_description=({additional_info}.*?);\s{1,100}(\w+=|$)""",
    """\Wfilename=({file_name}[^\.]{1,2000}\.({file_ext}.*?));\s{1,100}(\w+=|$)""",
    """\Wfiletype=({file_type}.*?);\s{1,100}(\w+=|$)""",
    """({direction}Outbound|Inbound)""",
    """Sent To:\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
  ]
  DupFields = [ "file_name->attachments" ]


}
```