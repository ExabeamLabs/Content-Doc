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
    """archive\[\d+\]:\s+({message_id}\S+)\s+({time}\d+).*?<({sender}[^\s@]+@({external_domain_sender}.+?))>\s+({recipient}[^\s@]+@({external_domain_recipient}.+?))\s+\S+\s+({direction}internal)"""
  ]
  DupFields = [ "recipient->recipients" ]
}
```