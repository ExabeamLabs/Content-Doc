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
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d{10})\.\d{6}\t({alert_id}[^\t]+)\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({src_port}\d+?)|[^\t]+))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({dest_port}\d+?)|[^\t]+))\t(?:-|({trans_depth}[^\t]+))\t(?:-|({helo}[^\t]+))\t(?:-|({mailfrom}[^\t]+))\t(?:-|({rcptto}[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t((?:-|({cc}[^\t]+))\t)?(?:-|({reply_to}[^\t]+))\t(?:-|(<)?({message_id}.+?)(>)?)\t(?:-|({in_reply_to}[^\t]+))\t(?:-|({subject}[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|({path}[^\t]+))\t(?:-|({user_agent}[^\t]+))\t(?:-|({tls}[^\t]+))\t(?:-|\((empty)\)|({attachments}[^\t]+))\t(?:-|([^\t]+?))\s*$""",
    """\d{10}\.\d{6}\t([^\t]+\t){7}({sender}[^@\t]+@({external_domain_sender}[^\t]+))\t""",
    """\d{10}\.\d{6}\t([^\t]+\t){8}({recipient}[^@\,\t]+@({external_domain_recipient}[^\,\t]+))""",
    """\d{10}\.\d{6}\t([^\t]+\t){20}({result_code}\d+)\s+({outcome}.+?)(\s*\t|\s*\[)((\[InternalId=({alert_id}\d+),\s*Hostname=({dest_host}[^\]]+)\]))?"""
  ]
}
```