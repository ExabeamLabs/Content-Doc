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
      """rt=({time}\d{1,100})""",
      """ahost=({host}[^\s]{1,2000})"""
      """dvchost=({dest_host}[^\s]{1,2000})""",
      """duser=({user}[\w\-\.\s]{1,2000}(?:\w+)?\$?)\s{1,100}\w+="""
      """dntdom=({domain}.+?)\s{1,100}\w+=""",
      """cs5=({subcategory}.+?)\s{1,100}\w+="""
      """cs6=({audit_category}.+?)\s{1,100}\w+="""
    ]
  }
```