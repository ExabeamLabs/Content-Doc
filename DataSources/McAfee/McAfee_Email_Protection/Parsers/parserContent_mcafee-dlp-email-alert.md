#### Parser Content
```Java
{
Name = mcafee-dlp-email-alert
    Vendor = McAfee
    Product = McAfee Email Protection
    Lms = Direct
    DataType = "dlp-email-alert"
    TimeFormat = "MM dd yyyy HH:mm:ss"
    Conditions = [ """Event='Email Status""" ]
    Fields = [
      """({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d)\s({host}\S+)\s(?i)<mail:info>""",
      """\sFrom=<({sender}[^>,;]+)""",
      """\sFrom=<[^@]+?@({external_domain_sender}[^>,;]+)""",
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