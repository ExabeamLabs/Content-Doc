#### Parser Content
```Java
{
Name = s-560-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ ",560,", """|NetApp Data ONTAP|""", "オブジェクト アクセス" ]
    Fields = [ 
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),560,""",
      """({event_code}560)""",
      """オブジェクトの種類:\s{1,100}({file_type}[^\s]{1,2000})\s{1,100}""",
      """オブジェクト名:\s{1,100}({file_path}.+?)\s{1,100}ハンドル ID:""",
      """オブジェクト名:\s{1,100}.*\\({file_name}(?:[^\\:]{1,2000}(?=\.))({file_ext}\.[^\\:\s]{1,2000})?|[^\\:\s]{1,2000})\s{0,100}ハンドル ID:""",
      """オブジェクト名:\s{1,100}({file_parent}.+?)\\(?:[^\\]{1,2000}?)\s{0,100}ハンドル ID:""",
      """プライマリ ユーザー名:\s{1,100}({user}[^\s]{1,2000})\s{1,100}""",
      """プライマリ ドメイン:\s{1,100}({domain}[^\s]{1,2000})\s{1,100}""",
      """プライマリ ログオン ID:\s{1,100}\([^,]{1,2000}
```