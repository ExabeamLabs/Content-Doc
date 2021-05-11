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
      """\sfrom=<({sender}[^>,;]+)""",
      """\sfrom=<[^@]+?@({external_domain_sender}[^>,;]+)""",
      """\ssize=({bytes}\d{1,100})""",
      """\ssource=({src_host}[^(,]+?)?\(({src_ip}[a-fA-F\d.:]+)""",
      """\snrcpts=({num_recipients}\d{1,100})""",
      """\sto=<({recipient}[^>,;]+)""",
      """\sto=<[^@]+?@({external_domain_recipient}[^>,;]+)""",
      """\sto=<({recipients}[^>]+?)>""",
      """\sstatus='({outcome}[^']+?)'""",
      """\ssubject='({subject}[^']+?)'""",
      """\sattachment\(s\)='({attachments}[^']+?)'""",
      """\snumber-attachment\(s\)='({num_attachments}\d{1,100})"""
    ]
  }
```