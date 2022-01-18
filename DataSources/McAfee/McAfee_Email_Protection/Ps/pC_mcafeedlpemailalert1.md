#### Parser Content
```Java
{
Name = mcafee-dlp-email-alert-1
    Vendor = McAfee
    Product = McAfee Email Protection
    Lms = Direct
    DataType = "dlp-email-alert"
    TimeFormat = "MM dd yyyy HH:mm:ss"
    Conditions = [ """event='email status""" ]
    Fields = [
      """(?i)({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d)\s({host}\S+)\s<mail:info>""",
      """\sfrom=<({sender}[^>,;]{1,2000})""",
      """\sfrom=<[^@]{1,2000}?@({external_domain_sender}[^>,;]{1,2000})""",
      """\ssize=({bytes}\d{1,100})""",
      """\ssource=({src_host}[^(,]{1,2000}?)?\(({src_ip}[a-fA-F\d.:]{1,2000})""",
      """\snrcpts=({num_recipients}\d{1,100})""",
      """\sto=<({recipient}[^>,;]{1,2000})""",
      """\sto=<[^@]{1,2000}?@({external_domain_recipient}[^>,;]{1,2000})""",
      """\sto=<({recipients}[^>]{1,2000}?)>""",
      """\sstatus='({outcome}[^']{1,2000}?)'""",
      """\ssubject='({subject}[^']{1,2000}?)'""",
      """\sattachment\(s\)='({attachments}[^']{1,2000}?)'""",
      """\snumber-attachment\(s\)='({num_attachments}\d{1,100})"""
    ]
  

}
```