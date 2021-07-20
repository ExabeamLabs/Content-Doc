#### Parser Content
```Java
{
Name = checkpoint-dlp-alert-out
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CheckPoint""", """from:""" , """to:""", """email_session_id"""]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) ({host}[\w.\-]{1,2000}) CheckPoint """,
    """\Wifdir:"({direction}[^"]{1,2000})""",
    """\Wifname:"({src_interface}[^"]{1,2000})""",
    """\Worigin:"({src_ip}[^"]{1,2000})""",
    """\Wfrom:"({sender}[^"@]{1,2000}@({external_domain_sender}[^"@]{1,2000}))""",
    """\Wto:"({recipients}({recipient}[^@"\s]{1,2000}@({external_domain_recipient}[^"@\s]{1,2000}))[^"]{0,2000}?)"""",
    """\Wemail_session_id:"({email_id}[^"]{1,2000})""",
  ]
}
```