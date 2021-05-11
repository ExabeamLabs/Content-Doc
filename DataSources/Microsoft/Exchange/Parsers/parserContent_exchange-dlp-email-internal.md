#### Parser Content
```Java
{
Name = exchange-dlp-email-internal
  Vendor = Microsoft
  Product = Exchange
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """archive[""", """ internal """ ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """archive\[\d{1,100}\]:\s{1,100}({message_id}\S+)\s{1,100}({time}\d{1,100}).*?<({sender}[^\s@]+@({external_domain_sender}.+?))>\s{1,100}({recipient}[^\s@]+@({external_domain_recipient}.+?))\s{1,100}\S+\s{1,100}({direction}internal)"""
  ]
  DupFields = [ "recipient->recipients" ]
}
```