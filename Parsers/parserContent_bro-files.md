#### Parser Content
```Java
{
Name = bro-files
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "file-read"
  TimeFormat = "epoch_sec"
  Conditions = [ "/files.log" ]
  Fields = [
      """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
      """({time}\d{10})\.\d{6}\t({file_id}[^\t]+)\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|({conn_uids}[^\t]+))\t(?:-|({protocol}[^\t]+))\t(?:-|({depth}[^\t]+))\t(?:-|({analyzers}[^\t]+))\t(?:-|({mime}[^\t]+))\t(?:-|([^\t]+))\t(?:-|({duration}[^\t]+))\t(?:-|({local_orig}[^\t]+))\t(?:-|({is_orig}[^\t]+))\t(?:-|({bytes}[^\t]+))\t(?:-|({total_bytes}[^\t]+))\t(?:-|({missing_bytes}[^\t]+))\t(?:-|({overflow_bytes}[^\t]+))\t(?:-|({timedout}[^\t]+))\t(?:-|({parent_file_id}[^\t]+))\t(?:-|({md5}[^\t]+))\t(?:-|({sha1}[^\t]+))\t(?:-|({sha256}[^\t]+))\t(?:-|({extracted}[^\t]+?))\s*""",
      """\d{10}\.\d{6}\t([^\t]+\t){22}(?:-|({extracted_cutoff}[^\t]+))\t(?:-|({extracted_size}[^\s]+))\s*$"""
      """\d{10}\.\d{6}\t([^\t]+\t){8}(?:-|({file_path}({file_parent}[^\s]*?(\\u005c|[\\\/])*)({file_name}[^\s\\\/]+?(\.({file_ext}[^\s\\\/\.]+))?)))\s*\\?\t"""
  ]
}
```