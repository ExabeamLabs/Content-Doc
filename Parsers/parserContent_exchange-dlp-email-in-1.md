#### Parser Content
```Java
{
Name = exchange-dlp-email-in-1
  Vendor = Microsoft
  Product = Exchange
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """archive[""", """ inbound """ ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """archive\[\d+\]:\s+({message_id}\S+)\s+({time}\d+).*?<({sender}[^\s@]+@({external_domain}.+?))>\s+({recipient}\S+)\s+\S+\s+({direction}inbound)"""
  ]
  DupFields = [ "recipient->recipients" ]
}
```