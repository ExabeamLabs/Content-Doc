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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """archive\[\d{1,100}\]:\s{1,100}({message_id}\S+)\s{1,100}({time}\d{1,100}).*?<({sender}[^\s@]{1,2000}@({external_domain}.+?))>\s{1,100}({recipient}\S+)\s{1,100}\S+\s{1,100}({direction}inbound)"""
  ]
  DupFields = [ "recipient->recipients" ]
}
```