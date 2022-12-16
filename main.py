# nox 漏洞更新钉钉通知 by Ahi http://blog.rip2.vip
# 数据来源 https://nox.qianxin.com
# 食用方法: 修改dingding token和 secret,计划任务定时运行即可
import sqlite3
import requests
import json
from urllib import parse
class nox: 
    def __init__(self):
        self.db_conn = sqlite3.connect('./db.db')
        self.db_cursor = self.db_conn.cursor()
        #钉钉机器人参数
        self.access_token='68e178b4063a7199bf8b182970746a359b7af4d37aeb5da4ccb62a80e65d1af7' #钉钉机器人webhook中access_token的值
        self.secret='SEC976334f3926fe789b710ad4b33a50e5c3531dc4b0403ff668d2082cf1e86c539' #钉钉机器人的secret值
        self.main()

    def __del__(self):
        self.db_conn.close()

    def main(self):
        url = 'https://nox.qianxin.com/api/web/portal/key_vuln/list'
        headers = {
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0',
            'Accept':'application/json, text/plain, */*',
            'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Content-Type':'application/json; charset=utf-8',
            'access-token':'da0d61ba189195d349d51214fff9008d',
            'key':':LXHGJYE72DNSR62KADVCIXVKGFWN5QEQ',
            'Referer':'https://nox.qianxin.com/KeyPoint'
        }

        data = '{"page_no":1,"page_size":10,"vuln_keyword":""}'
        resp = requests.post(url=url,data =data ,headers =headers);
        resp_data = json.loads(resp.content)
        if int(resp_data['resp_code']) == 0 and str(resp_data['resp_message']) == 'success':
            if int(resp_data['data']['total']) >0:
                for item in resp_data['data']['data']:
                    vulns={};
                    vulns['id'] = item['id'] #漏洞ID
                    vulns['vuln_name'] = item['vuln_name'] #漏洞名
                    vulns['qvd_code'] = item['qvd_code'] #qvd编号
                    vulns['cve_code'] = item['cve_code'] #cve编号
                    vulns['description'] = item['description'] #漏洞描述
                    vulns['publish_time'] = item['publish_time'] #公开日期
                    vulns['vuln_type'] = item['vuln_type'] #威胁类型
                    vulns['poc_flag'] = item['poc_flag']  #是否有poc
                    vulns['rating_level'] = item['rating_level'] #威胁等级
                    vulns['tags'] = [] #标签
                    for tag in item['tag']:
                        vulns['tags'].append(tag['name'])                   
                    self.insert_db(vulns)
    def insert_db(self,data):
        #查询数据库记录是否存在
        cursor = self.db_cursor.execute("SELECT id  from vuln where id=" + str(data['id']))
        sql_data = cursor.fetchone()
        if sql_data  is None:
            sql = "insert into vuln values('%d');"%data['id']
            res =self.db_cursor.execute(sql)
            res.lastrowid
            self.db_conn.commit()
            if(res.lastrowid):
                print('数据插入成功:',data)
                self.dingding(data)
            else:
                print('数据插入失败:',data)
        else:
            print('数据已存在:',data)

    def dingding(self,data):
        # 钉钉api
        api = 'http://api.rip2.vip/msg/ding'

        msgtype = 'text'
        content =  self.format_msg(data)
        url = api + '?access_token='+ self.access_token + '&secret=' + self.secret +'&msgtype=' + msgtype +'&content=' + content
        requests.get(url)
    
    def format_msg(self,data):
        if(data['poc_flag'] ==1):
            data['poc_flag'] = '有'
        else:
            data['poc_flag'] = '无'

        url = 'https://nox.qianxin.com/vulnerability/detail/'+data['qvd_code']
        msg = "漏洞名:%(vuln_name)s \n qvd编号:%(qvd_code)s \n cve编号:%(cve_code)s \n 威胁类型:%(vuln_type)s \n 是否有poc:%(poc_flag)s \n 威胁等级:%(rating_level)s \n 标签:%(tags)s \n 公开日期:%(publish_time)s \n 漏洞描述:%(description)s \n 详情:%(url)s"%{"vuln_name":data['vuln_name'],"qvd_code":data['qvd_code'],"cve_code":data['cve_code'],"vuln_type":data['vuln_type'],"poc_flag":data['poc_flag'],"rating_level":data['rating_level'],"tags":data['tags'],"publish_time":data['publish_time'],"description":data['description'],'url':url}
        return parse.quote(str(msg))

if __name__ == '__main__':
   nox = nox();
