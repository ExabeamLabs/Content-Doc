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
      """exabeam_host=({host}[\w.\-]+)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),560,""",
      """({event_code}560)""",
      """オブジェクトの種類:\s{1,100}({file_type}[^\s]+)\s{1,100}""",
      """オブジェクト名:\s{1,100}({file_path}.+?)\s{1,100}ハンドル ID:""",
      """オブジェクト名:\s{1,100}.*\\({file_name}(?:[^\\:]+(?=\.))({file_ext}\.[^\\:\s]+)?|[^\\:\s]+)\s{0,100}ハンドル ID:""",
      """オブジェクト名:\s{1,100}({file_parent}.+?)\\(?:[^\\]+?)\s{0,100}ハンドル ID:""",
      """プライマリ ユーザー名:\s{1,100}({user}[^\s]+)\s{1,100}""",
      """プライマリ ドメイン:\s{1,100}({domain}[^\s]+)\s{1,100}""",
      """プライマリ ログオン ID:\s{1,100}\([^,]+,\s{0,100}({logon_id}[^)]+)""",
      """イメージ ファイル名:\s{1,100}({process_name}.+?)\s{1,100}プライマリ ユーザー名:""",
      """クライアント ユーザー名:\s{1,100}({src_ip}[A-Fa-f:\d.]+)""",
      """アクセス数:\s{1,100}({accesses}.+?)\s{1,100}特権:"""
    ]
  }
```