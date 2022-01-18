#### Parser Content
```Java
{
Name = bro-smtp
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ "/smtp.log" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d{10})\.\d{6}\t({alert_id}[^\t]{1,2000})\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({src_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({dest_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|({trans_depth}[^\t]{1,2000}))\t(?:-|({helo}[^\t]{1,2000}))\t(?:-|({mailfrom}[^\t]{1,2000}))\t(?:-|({rcptto}[^\t]{1,2000}))\t(?:-|([^\t]{1,2000}))\t(?:-|([^\t]{1,2000}))\t(?:-|([^\t]{1,2000}))\t((?:-|({cc}[^\t]{1,2000}))\t)?(?:-|({reply_to}[^\t]{1,2000}))\t(?:-|(<)?({message_id}.+?)(>)?)\t(?:-|({in_reply_to}[^\t]{1,2000}))\t(?:-|({subject}[^\t]{1,2000}))\t(?:-|([^\t]{1,2000}))\t(?:-|([^\t]{1,2000}))\t(?:-|([^\t]{1,2000}))\t(?:-|([^\t]{1,2000}))\t(?:-|({path}[^\t]{1,2000}))\t(?:-|({user_agent}[^\t]{1,2000}))\t(?:-|({tls}[^\t]{1,2000}))\t(?:-|\((empty)\)|({attachments}[^\t]{1,2000}))\t(?:-|([^\t]{1,2000}?))\s{0,100}$""",
    """\d{10}\.\d{6}\t([^\t]{1,2000}\t){7}({sender}[^@\t]{1,2000}@({external_domain_sender}[^\t]{1,2000}))\t""",
    """\d{10}\.\d{6}\t([^\t]{1,2000}\t){8}({recipient}[^@\,\t]{1,2000}@({external_domain_recipient}[^\,\t]{1,2000}))""",
    """\d{10}\.\d{6}\t([^\t]{1,2000}\t){20}({result_code}\d{1,100})\s{1,100}({outcome}.+?)(\s{0,100}\t|\s{0,100}\[)((\[InternalId=({alert_id}\d{1,100}),\s{0,100}Hostname=({dest_host}[^\]]{1,2000})\]))?"""
  ]


}
```