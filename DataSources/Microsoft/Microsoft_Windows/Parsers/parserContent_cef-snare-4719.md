#### Parser Content
```Java
{
Name = cef-snare-4719
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-audit"
    TimeFormat = "epoch"
    Conditions = ["|Snare|", "|Microsoft-Windows-Security-Auditing:4719|System audit policy was changed|"]
    Fields = [
      """({event_name}System audit policy was changed)""",
      """({event_code}4719)"""
      """rt=({time}\d+)""",
      """ahost=({host}[^\s]+)"""
      """dvchost=({dest_host}[^\s]+)""",
      """duser=({user}[\w\-\.\s]+(?:\w+)?\$?)\s+\w+="""
      """dntdom=({domain}.+?)\s+\w+=""",
      """cs5=({subcategory}.+?)\s+\w+="""
      """cs6=({audit_category}.+?)\s+\w+="""
    ]
  }
```