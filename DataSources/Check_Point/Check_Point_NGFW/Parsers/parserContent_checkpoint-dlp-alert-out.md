#### Parser Content
```Java
{
Name = checkpoint-dlp-alert-out
  Vendor = Check Point
  Product = Check Point NGFW
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CheckPoint""", """from:""" , """to:""", """email_session_id"""]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) ({host}[\w.\-]+) CheckPoint """,
    """\Wifdir:"({direction}[^"]+)""",
    """\Wifname:"({src_interface}[^"]+)""",
    """\Worigin:"({src_ip}[^"]+)""",
    """\Wfrom:"({sender}[^"@]+@({external_domain_sender}[^"@]+))""",
    """\Wto:"({recipients}({recipient}[^@"\s]+@({external_domain_recipient}[^"@\s]+))[^"]*?)"""",
    """\Wemail_session_id:"({email_id}[^"]+)""",
  ]
}
```