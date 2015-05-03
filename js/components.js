require=function e(t,r,i){function n(o,s){if(!r[o]){if(!t[o]){var c="function"==typeof require&&require;if(!s&&c)return c(o,!0);if(a)return a(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var d=r[o]={exports:{}};t[o][0].call(d.exports,function(e){var r=t[o][1][e];return n(r?r:e)},d,d.exports,e,t,r,i)}return r[o].exports}for(var a="function"==typeof require&&require,o=0;o<i.length;o++)n(i[o]);return n}({1:[function(e,t,r){"use strict";var i={name:"Mnemonic",message:"Internal Error on bitcore-mnemonic module {0}",errors:[{name:"InvalidEntropy",message:"Entropy length must be an even multiple of 11 bits: {0}"},{name:"UnknownWordlist",message:"Could not detect the used word list: {0}"},{name:"InvalidMnemonic",message:"Mnemonic string is invalid: {0}"}]};t.exports=e("bitcore").errors.extend(i)},{bitcore:"bitcore"}],2:[function(e,t,r){(function(r){"use strict";var i=e("bitcore"),n=i.deps._,a=e("./pbkdf2"),o=e("./errors"),s=i.crypto.Hash,c=i.crypto.Random,f=i.util.preconditions,d=function(e,t){if(!(this instanceof d))return new d(e,t);n.isArray(e)&&(t=e,e=null);var a,s,c;if(r.isBuffer(e))c=e;else if(n.isString(e))s=e;else if(n.isNumber(e))a=e;else if(e)throw new i.errors.InvalidArgument("data","Must be a Buffer, a string or an integer");if(a=a||128,t=t||d._getDictionary(s),s&&!t)throw new o.UnknownWordlist(s);if(t=t||d.Words.ENGLISH,c&&(s=d._entropy2mnemonic(c,t)),s&&!d.isValid(s,t))throw new o.InvalidMnemonic(s);if(a%32!==0||128>a)throw new i.errors.InvalidArgument("ENT","Values must be ENT > 128 and ENT % 32 == 0");s=s||d._mnemonic(a,t),Object.defineProperty(this,"wordlist",{configurable:!1,value:t}),Object.defineProperty(this,"phrase",{configurable:!1,value:s})};d.Words=e("./words"),d.isValid=function(e,t){if(t=t||d._getDictionary(e),!t)return!1;for(var i=e.split(" "),n="",a=0;a<i.length;a++){var o=t.indexOf(i[a]);if(0>o)return!1;n+=("00000000000"+o.toString(2)).slice(-11)}var s=n.length/33,c=n.slice(-s),f=n.slice(0,n.length-s),u=new r(f.length/8);for(a=0;a<f.length/8;a++)u.writeUInt8(parseInt(n.slice(8*a,8*(a+1)),2),a);var h=d._entropyChecksum(u);return h===c},d._belongsToWordlist=function(e,t){var r=e.split(" ")[0];return-1!==t.indexOf(r)},d._getDictionary=function(e){if(!e)return null;for(var t=Object.keys(d.Words),r=0;r<t.length;r++){var i=t[r];if(d._belongsToWordlist(e,d.Words[i]))return d.Words[i]}return null},d.prototype.toSeed=function(e){return e=e||"",a(this.phrase,"mnemonic"+e,2048,64)},d.fromSeed=function(e,t){return f.checkArgument(r.isBuffer(e),"seed must be a Buffer."),f.checkArgument(n.isArray(t)||n.isString(t),"wordlist must be a string or an array."),new d(e,t)},d.prototype.toHDPrivateKey=function(e,t){var r=this.toSeed(e);return i.HDPrivateKey.fromSeed(r,t)},d.prototype.toString=function(){return this.phrase},d.prototype.inspect=function(){return"<Mnemonic: "+this.toString()+" >"},d._mnemonic=function(e,t){var r=c.getRandomBuffer(e/8);return d._entropy2mnemonic(r,t)},d._entropy2mnemonic=function(e,t){for(var r="",i=0;i<e.length;i++)r+=("00000000"+e[i].toString(2)).slice(-8);if(r+=d._entropyChecksum(e),r.length%11!==0)throw new o.InvalidEntropy(r);var n=[];for(i=0;i<r.length/11;i++){var a=parseInt(r.slice(11*i,11*(i+1)),2);n.push(t[a])}return n.join(" ")},d._entropyChecksum=function(e){var t=s.sha256(e),r=8*e.length,i=r/32,n=parseInt(t.toString("hex"),16).toString(2);return n=(new Array(256).join("0")+n).slice(-256).slice(0,i)},t.exports=d}).call(this,e("buffer").Buffer)},{"./errors":1,"./pbkdf2":3,"./words":6,bitcore:"bitcore",buffer:9}],3:[function(e,t,r){(function(r){"use strict";function i(e,t,i,a){var o=64;if(a>(Math.pow(2,32)-1)*o)throw Error("Requested key length too long");if("string"!=typeof e&&!r.isBuffer(e))throw new TypeError("key must a string or Buffer");if("string"!=typeof t&&!r.isBuffer(t))throw new TypeError("salt must a string or Buffer");"string"==typeof t&&(t=new r(t));var s=new r(a),c=new r(o),f=new r(o),d=new r(t.length+4),u=Math.ceil(a/o),h=a-(u-1)*o;t.copy(d,0,0,t.length);for(var l=1;u>=l;l++){d[t.length+0]=l>>24&255,d[t.length+1]=l>>16&255,d[t.length+2]=l>>8&255,d[t.length+3]=l>>0&255,c=n.createHmac("sha512",e).update(d).digest(),c.copy(f,0,0,o);for(var b=1;i>b;b++){c=n.createHmac("sha512",e).update(c).digest();for(var p=0;o>p;p++)f[p]^=c[p]}var m=(l-1)*o,g=l===u?h:o;f.copy(s,m,0,g)}return s}var n=e("crypto");t.exports=i}).call(this,e("buffer").Buffer)},{buffer:9,crypto:13}],4:[function(e,t,r){"use strict";var i=["的","一","是","在","不","了","有","和","人","这","中","大","为","上","个","国","我","以","要","他","时","来","用","们","生","到","作","地","于","出","就","分","对","成","会","可","主","发","年","动","同","工","也","能","下","过","子","说","产","种","面","而","方","后","多","定","行","学","法","所","民","得","经","十","三","之","进","着","等","部","度","家","电","力","里","如","水","化","高","自","二","理","起","小","物","现","实","加","量","都","两","体","制","机","当","使","点","从","业","本","去","把","性","好","应","开","它","合","还","因","由","其","些","然","前","外","天","政","四","日","那","社","义","事","平","形","相","全","表","间","样","与","关","各","重","新","线","内","数","正","心","反","你","明","看","原","又","么","利","比","或","但","质","气","第","向","道","命","此","变","条","只","没","结","解","问","意","建","月","公","无","系","军","很","情","者","最","立","代","想","已","通","并","提","直","题","党","程","展","五","果","料","象","员","革","位","入","常","文","总","次","品","式","活","设","及","管","特","件","长","求","老","头","基","资","边","流","路","级","少","图","山","统","接","知","较","将","组","见","计","别","她","手","角","期","根","论","运","农","指","几","九","区","强","放","决","西","被","干","做","必","战","先","回","则","任","取","据","处","队","南","给","色","光","门","即","保","治","北","造","百","规","热","领","七","海","口","东","导","器","压","志","世","金","增","争","济","阶","油","思","术","极","交","受","联","什","认","六","共","权","收","证","改","清","美","再","采","转","更","单","风","切","打","白","教","速","花","带","安","场","身","车","例","真","务","具","万","每","目","至","达","走","积","示","议","声","报","斗","完","类","八","离","华","名","确","才","科","张","信","马","节","话","米","整","空","元","况","今","集","温","传","土","许","步","群","广","石","记","需","段","研","界","拉","林","律","叫","且","究","观","越","织","装","影","算","低","持","音","众","书","布","复","容","儿","须","际","商","非","验","连","断","深","难","近","矿","千","周","委","素","技","备","半","办","青","省","列","习","响","约","支","般","史","感","劳","便","团","往","酸","历","市","克","何","除","消","构","府","称","太","准","精","值","号","率","族","维","划","选","标","写","存","候","毛","亲","快","效","斯","院","查","江","型","眼","王","按","格","养","易","置","派","层","片","始","却","专","状","育","厂","京","识","适","属","圆","包","火","住","调","满","县","局","照","参","红","细","引","听","该","铁","价","严","首","底","液","官","德","随","病","苏","失","尔","死","讲","配","女","黄","推","显","谈","罪","神","艺","呢","席","含","企","望","密","批","营","项","防","举","球","英","氧","势","告","李","台","落","木","帮","轮","破","亚","师","围","注","远","字","材","排","供","河","态","封","另","施","减","树","溶","怎","止","案","言","士","均","武","固","叶","鱼","波","视","仅","费","紧","爱","左","章","早","朝","害","续","轻","服","试","食","充","兵","源","判","护","司","足","某","练","差","致","板","田","降","黑","犯","负","击","范","继","兴","似","余","坚","曲","输","修","故","城","夫","够","送","笔","船","占","右","财","吃","富","春","职","觉","汉","画","功","巴","跟","虽","杂","飞","检","吸","助","升","阳","互","初","创","抗","考","投","坏","策","古","径","换","未","跑","留","钢","曾","端","责","站","简","述","钱","副","尽","帝","射","草","冲","承","独","令","限","阿","宣","环","双","请","超","微","让","控","州","良","轴","找","否","纪","益","依","优","顶","础","载","倒","房","突","坐","粉","敌","略","客","袁","冷","胜","绝","析","块","剂","测","丝","协","诉","念","陈","仍","罗","盐","友","洋","错","苦","夜","刑","移","频","逐","靠","混","母","短","皮","终","聚","汽","村","云","哪","既","距","卫","停","烈","央","察","烧","迅","境","若","印","洲","刻","括","激","孔","搞","甚","室","待","核","校","散","侵","吧","甲","游","久","菜","味","旧","模","湖","货","损","预","阻","毫","普","稳","乙","妈","植","息","扩","银","语","挥","酒","守","拿","序","纸","医","缺","雨","吗","针","刘","啊","急","唱","误","训","愿","审","附","获","茶","鲜","粮","斤","孩","脱","硫","肥","善","龙","演","父","渐","血","欢","械","掌","歌","沙","刚","攻","谓","盾","讨","晚","粒","乱","燃","矛","乎","杀","药","宁","鲁","贵","钟","煤","读","班","伯","香","介","迫","句","丰","培","握","兰","担","弦","蛋","沉","假","穿","执","答","乐","谁","顺","烟","缩","征","脸","喜","松","脚","困","异","免","背","星","福","买","染","井","概","慢","怕","磁","倍","祖","皇","促","静","补","评","翻","肉","践","尼","衣","宽","扬","棉","希","伤","操","垂","秋","宜","氢","套","督","振","架","亮","末","宪","庆","编","牛","触","映","雷","销","诗","座","居","抓","裂","胞","呼","娘","景","威","绿","晶","厚","盟","衡","鸡","孙","延","危","胶","屋","乡","临","陆","顾","掉","呀","灯","岁","措","束","耐","剧","玉","赵","跳","哥","季","课","凯","胡","额","款","绍","卷","齐","伟","蒸","殖","永","宗","苗","川","炉","岩","弱","零","杨","奏","沿","露","杆","探","滑","镇","饭","浓","航","怀","赶","库","夺","伊","灵","税","途","灭","赛","归","召","鼓","播","盘","裁","险","康","唯","录","菌","纯","借","糖","盖","横","符","私","努","堂","域","枪","润","幅","哈","竟","熟","虫","泽","脑","壤","碳","欧","遍","侧","寨","敢","彻","虑","斜","薄","庭","纳","弹","饲","伸","折","麦","湿","暗","荷","瓦","塞","床","筑","恶","户","访","塔","奇","透","梁","刀","旋","迹","卡","氯","遇","份","毒","泥","退","洗","摆","灰","彩","卖","耗","夏","择","忙","铜","献","硬","予","繁","圈","雪","函","亦","抽","篇","阵","阴","丁","尺","追","堆","雄","迎","泛","爸","楼","避","谋","吨","野","猪","旗","累","偏","典","馆","索","秦","脂","潮","爷","豆","忽","托","惊","塑","遗","愈","朱","替","纤","粗","倾","尚","痛","楚","谢","奋","购","磨","君","池","旁","碎","骨","监","捕","弟","暴","割","贯","殊","释","词","亡","壁","顿","宝","午","尘","闻","揭","炮","残","冬","桥","妇","警","综","招","吴","付","浮","遭","徐","您","摇","谷","赞","箱","隔","订","男","吹","园","纷","唐","败","宋","玻","巨","耕","坦","荣","闭","湾","键","凡","驻","锅","救","恩","剥","凝","碱","齿","截","炼","麻","纺","禁","废","盛","版","缓","净","睛","昌","婚","涉","筒","嘴","插","岸","朗","庄","街","藏","姑","贸","腐","奴","啦","惯","乘","伙","恢","匀","纱","扎","辩","耳","彪","臣","亿","璃","抵","脉","秀","萨","俄","网","舞","店","喷","纵","寸","汗","挂","洪","贺","闪","柬","爆","烯","津","稻","墙","软","勇","像","滚","厘","蒙","芳","肯","坡","柱","荡","腿","仪","旅","尾","轧","冰","贡","登","黎","削","钻","勒","逃","障","氨","郭","峰","币","港","伏","轨","亩","毕","擦","莫","刺","浪","秘","援","株","健","售","股","岛","甘","泡","睡","童","铸","汤","阀","休","汇","舍","牧","绕","炸","哲","磷","绩","朋","淡","尖","启","陷","柴","呈","徒","颜","泪","稍","忘","泵","蓝","拖","洞","授","镜","辛","壮","锋","贫","虚","弯","摩","泰","幼","廷","尊","窗","纲","弄","隶","疑","氏","宫","姐","震","瑞","怪","尤","琴","循","描","膜","违","夹","腰","缘","珠","穷","森","枝","竹","沟","催","绳","忆","邦","剩","幸","浆","栏","拥","牙","贮","礼","滤","钠","纹","罢","拍","咱","喊","袖","埃","勤","罚","焦","潜","伍","墨","欲","缝","姓","刊","饱","仿","奖","铝","鬼","丽","跨","默","挖","链","扫","喝","袋","炭","污","幕","诸","弧","励","梅","奶","洁","灾","舟","鉴","苯","讼","抱","毁","懂","寒","智","埔","寄","届","跃","渡","挑","丹","艰","贝","碰","拔","爹","戴","码","梦","芽","熔","赤","渔","哭","敬","颗","奔","铅","仲","虎","稀","妹","乏","珍","申","桌","遵","允","隆","螺","仓","魏","锐","晓","氮","兼","隐","碍","赫","拨","忠","肃","缸","牵","抢","博","巧","壳","兄","杜","讯","诚","碧","祥","柯","页","巡","矩","悲","灌","龄","伦","票","寻","桂","铺","圣","恐","恰","郑","趣","抬","荒","腾","贴","柔","滴","猛","阔","辆","妻","填","撤","储","签","闹","扰","紫","砂","递","戏","吊","陶","伐","喂","疗","瓶","婆","抚","臂","摸","忍","虾","蜡","邻","胸","巩","挤","偶","弃","槽","劲","乳","邓","吉","仁","烂","砖","租","乌","舰","伴","瓜","浅","丙","暂","燥","橡","柳","迷","暖","牌","秧","胆","详","簧","踏","瓷","谱","呆","宾","糊","洛","辉","愤","竞","隙","怒","粘","乃","绪","肩","籍","敏","涂","熙","皆","侦","悬","掘","享","纠","醒","狂","锁","淀","恨","牲","霸","爬","赏","逆","玩","陵","祝","秒","浙","貌","役","彼","悉","鸭","趋","凤","晨","畜","辈","秩","卵","署","梯","炎","滩","棋","驱","筛","峡","冒","啥","寿","译","浸","泉","帽","迟","硅","疆","贷","漏","稿","冠","嫩","胁","芯","牢","叛","蚀","奥","鸣","岭","羊","凭","串","塘","绘","酵","融","盆","锡","庙","筹","冻","辅","摄","袭","筋","拒","僚","旱","钾","鸟","漆","沈","眉","疏","添","棒","穗","硝","韩","逼","扭","侨","凉","挺","碗","栽","炒","杯","患","馏","劝","豪","辽","勃","鸿","旦","吏","拜","狗","埋","辊","掩","饮","搬","骂","辞","勾","扣","估","蒋","绒","雾","丈","朵","姆","拟","宇","辑","陕","雕","偿","蓄","崇","剪","倡","厅","咬","驶","薯","刷","斥","番","赋","奉","佛","浇","漫","曼","扇","钙","桃","扶","仔","返","俗","亏","腔","鞋","棱","覆","框","悄","叔","撞","骗","勘","旺","沸","孤","吐","孟","渠","屈","疾","妙","惜","仰","狠","胀","谐","抛","霉","桑","岗","嘛","衰","盗","渗","脏","赖","涌","甜","曹","阅","肌","哩","厉","烃","纬","毅","昨","伪","症","煮","叹","钉","搭","茎","笼","酷","偷","弓","锥","恒","杰","坑","鼻","翼","纶","叙","狱","逮","罐","络","棚","抑","膨","蔬","寺","骤","穆","冶","枯","册","尸","凸","绅","坯","牺","焰","轰","欣","晋","瘦","御","锭","锦","丧","旬","锻","垄","搜","扑","邀","亭","酯","迈","舒","脆","酶","闲","忧","酚","顽","羽","涨","卸","仗","陪","辟","惩","杭","姚","肚","捉","飘","漂","昆","欺","吾","郎","烷","汁","呵","饰","萧","雅","邮","迁","燕","撒","姻","赴","宴","烦","债","帐","斑","铃","旨","醇","董","饼","雏","姿","拌","傅","腹","妥","揉","贤","拆","歪","葡","胺","丢","浩","徽","昂","垫","挡","览","贪","慰","缴","汪","慌","冯","诺","姜","谊","凶","劣","诬","耀","昏","躺","盈","骑","乔","溪","丛","卢","抹","闷","咨","刮","驾","缆","悟","摘","铒","掷","颇","幻","柄","惠","惨","佳","仇","腊","窝","涤","剑","瞧","堡","泼","葱","罩","霍","捞","胎","苍","滨","俩","捅","湘","砍","霞","邵","萄","疯","淮","遂","熊","粪","烘","宿","档","戈","驳","嫂","裕","徙","箭","捐","肠","撑","晒","辨","殿","莲","摊","搅","酱","屏","疫","哀","蔡","堵","沫","皱","畅","叠","阁","莱","敲","辖","钩","痕","坝","巷","饿","祸","丘","玄","溜","曰","逻","彭","尝","卿","妨","艇","吞","韦","怨","矮","歇"];t.exports=i},{}],5:[function(e,t,r){"use strict";var i=["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act","action","actor","actress","actual","adapt","add","addict","address","adjust","admit","adult","advance","advice","aerobic","affair","afford","afraid","again","age","agent","agree","ahead","aim","air","airport","aisle","alarm","album","alcohol","alert","alien","all","alley","allow","almost","alone","alpha","already","also","alter","always","amateur","amazing","among","amount","amused","analyst","anchor","ancient","anger","angle","angry","animal","ankle","announce","annual","another","answer","antenna","antique","anxiety","any","apart","apology","appear","apple","approve","april","arch","arctic","area","arena","argue","arm","armed","armor","army","around","arrange","arrest","arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault","asset","assist","assume","asthma","athlete","atom","attack","attend","attitude","attract","auction","audit","august","aunt","author","auto","autumn","average","avocado","avoid","awake","aware","away","awesome","awful","awkward","axis","baby","bachelor","bacon","badge","bag","balance","balcony","ball","bamboo","banana","banner","bar","barely","bargain","barrel","base","basic","basket","battle","beach","bean","beauty","because","become","beef","before","begin","behave","behind","believe","below","belt","bench","benefit","best","betray","better","between","beyond","bicycle","bid","bike","bind","biology","bird","birth","bitter","black","blade","blame","blanket","blast","bleak","bless","blind","blood","blossom","blouse","blue","blur","blush","board","boat","body","boil","bomb","bone","bonus","book","boost","border","boring","borrow","boss","bottom","bounce","box","boy","bracket","brain","brand","brass","brave","bread","breeze","brick","bridge","brief","bright","bring","brisk","broccoli","broken","bronze","broom","brother","brown","brush","bubble","buddy","budget","buffalo","build","bulb","bulk","bullet","bundle","bunker","burden","burger","burst","bus","business","busy","butter","buyer","buzz","cabbage","cabin","cable","cactus","cage","cake","call","calm","camera","camp","can","canal","cancel","candy","cannon","canoe","canvas","canyon","capable","capital","captain","car","carbon","card","cargo","carpet","carry","cart","case","cash","casino","castle","casual","cat","catalog","catch","category","cattle","caught","cause","caution","cave","ceiling","celery","cement","census","century","cereal","certain","chair","chalk","champion","change","chaos","chapter","charge","chase","chat","cheap","check","cheese","chef","cherry","chest","chicken","chief","child","chimney","choice","choose","chronic","chuckle","chunk","churn","cigar","cinnamon","circle","citizen","city","civil","claim","clap","clarify","claw","clay","clean","clerk","clever","click","client","cliff","climb","clinic","clip","clock","clog","close","cloth","cloud","clown","club","clump","cluster","clutch","coach","coast","coconut","code","coffee","coil","coin","collect","color","column","combine","come","comfort","comic","common","company","concert","conduct","confirm","congress","connect","consider","control","convince","cook","cool","copper","copy","coral","core","corn","correct","cost","cotton","couch","country","couple","course","cousin","cover","coyote","crack","cradle","craft","cram","crane","crash","crater","crawl","crazy","cream","credit","creek","crew","cricket","crime","crisp","critic","crop","cross","crouch","crowd","crucial","cruel","cruise","crumble","crunch","crush","cry","crystal","cube","culture","cup","cupboard","curious","current","curtain","curve","cushion","custom","cute","cycle","dad","damage","damp","dance","danger","daring","dash","daughter","dawn","day","deal","debate","debris","decade","december","decide","decline","decorate","decrease","deer","defense","define","defy","degree","delay","deliver","demand","demise","denial","dentist","deny","depart","depend","deposit","depth","deputy","derive","describe","desert","design","desk","despair","destroy","detail","detect","develop","device","devote","diagram","dial","diamond","diary","dice","diesel","diet","differ","digital","dignity","dilemma","dinner","dinosaur","direct","dirt","disagree","discover","disease","dish","dismiss","disorder","display","distance","divert","divide","divorce","dizzy","doctor","document","dog","doll","dolphin","domain","donate","donkey","donor","door","dose","double","dove","draft","dragon","drama","drastic","draw","dream","dress","drift","drill","drink","drip","drive","drop","drum","dry","duck","dumb","dune","during","dust","dutch","duty","dwarf","dynamic","eager","eagle","early","earn","earth","easily","east","easy","echo","ecology","economy","edge","edit","educate","effort","egg","eight","either","elbow","elder","electric","elegant","element","elephant","elevator","elite","else","embark","embody","embrace","emerge","emotion","employ","empower","empty","enable","enact","end","endless","endorse","enemy","energy","enforce","engage","engine","enhance","enjoy","enlist","enough","enrich","enroll","ensure","enter","entire","entry","envelope","episode","equal","equip","era","erase","erode","erosion","error","erupt","escape","essay","essence","estate","eternal","ethics","evidence","evil","evoke","evolve","exact","example","excess","exchange","excite","exclude","excuse","execute","exercise","exhaust","exhibit","exile","exist","exit","exotic","expand","expect","expire","explain","expose","express","extend","extra","eye","eyebrow","fabric","face","faculty","fade","faint","faith","fall","false","fame","family","famous","fan","fancy","fantasy","farm","fashion","fat","fatal","father","fatigue","fault","favorite","feature","february","federal","fee","feed","feel","female","fence","festival","fetch","fever","few","fiber","fiction","field","figure","file","film","filter","final","find","fine","finger","finish","fire","firm","first","fiscal","fish","fit","fitness","fix","flag","flame","flash","flat","flavor","flee","flight","flip","float","flock","floor","flower","fluid","flush","fly","foam","focus","fog","foil","fold","follow","food","foot","force","forest","forget","fork","fortune","forum","forward","fossil","foster","found","fox","fragile","frame","frequent","fresh","friend","fringe","frog","front","frost","frown","frozen","fruit","fuel","fun","funny","furnace","fury","future","gadget","gain","galaxy","gallery","game","gap","garage","garbage","garden","garlic","garment","gas","gasp","gate","gather","gauge","gaze","general","genius","genre","gentle","genuine","gesture","ghost","giant","gift","giggle","ginger","giraffe","girl","give","glad","glance","glare","glass","glide","glimpse","globe","gloom","glory","glove","glow","glue","goat","goddess","gold","good","goose","gorilla","gospel","gossip","govern","gown","grab","grace","grain","grant","grape","grass","gravity","great","green","grid","grief","grit","grocery","group","grow","grunt","guard","guess","guide","guilt","guitar","gun","gym","habit","hair","half","hammer","hamster","hand","happy","harbor","hard","harsh","harvest","hat","have","hawk","hazard","head","health","heart","heavy","hedgehog","height","hello","helmet","help","hen","hero","hidden","high","hill","hint","hip","hire","history","hobby","hockey","hold","hole","holiday","hollow","home","honey","hood","hope","horn","horror","horse","hospital","host","hotel","hour","hover","hub","huge","human","humble","humor","hundred","hungry","hunt","hurdle","hurry","hurt","husband","hybrid","ice","icon","idea","identify","idle","ignore","ill","illegal","illness","image","imitate","immense","immune","impact","impose","improve","impulse","inch","include","income","increase","index","indicate","indoor","industry","infant","inflict","inform","inhale","inherit","initial","inject","injury","inmate","inner","innocent","input","inquiry","insane","insect","inside","inspire","install","intact","interest","into","invest","invite","involve","iron","island","isolate","issue","item","ivory","jacket","jaguar","jar","jazz","jealous","jeans","jelly","jewel","job","join","joke","journey","joy","judge","juice","jump","jungle","junior","junk","just","kangaroo","keen","keep","ketchup","key","kick","kid","kidney","kind","kingdom","kiss","kit","kitchen","kite","kitten","kiwi","knee","knife","knock","know","lab","label","labor","ladder","lady","lake","lamp","language","laptop","large","later","latin","laugh","laundry","lava","law","lawn","lawsuit","layer","lazy","leader","leaf","learn","leave","lecture","left","leg","legal","legend","leisure","lemon","lend","length","lens","leopard","lesson","letter","level","liar","liberty","library","license","life","lift","light","like","limb","limit","link","lion","liquid","list","little","live","lizard","load","loan","lobster","local","lock","logic","lonely","long","loop","lottery","loud","lounge","love","loyal","lucky","luggage","lumber","lunar","lunch","luxury","lyrics","machine","mad","magic","magnet","maid","mail","main","major","make","mammal","man","manage","mandate","mango","mansion","manual","maple","marble","march","margin","marine","market","marriage","mask","mass","master","match","material","math","matrix","matter","maximum","maze","meadow","mean","measure","meat","mechanic","medal","media","melody","melt","member","memory","mention","menu","mercy","merge","merit","merry","mesh","message","metal","method","middle","midnight","milk","million","mimic","mind","minimum","minor","minute","miracle","mirror","misery","miss","mistake","mix","mixed","mixture","mobile","model","modify","mom","moment","monitor","monkey","monster","month","moon","moral","more","morning","mosquito","mother","motion","motor","mountain","mouse","move","movie","much","muffin","mule","multiply","muscle","museum","mushroom","music","must","mutual","myself","mystery","myth","naive","name","napkin","narrow","nasty","nation","nature","near","neck","need","negative","neglect","neither","nephew","nerve","nest","net","network","neutral","never","news","next","nice","night","noble","noise","nominee","noodle","normal","north","nose","notable","note","nothing","notice","novel","now","nuclear","number","nurse","nut","oak","obey","object","oblige","obscure","observe","obtain","obvious","occur","ocean","october","odor","off","offer","office","often","oil","okay","old","olive","olympic","omit","once","one","onion","online","only","open","opera","opinion","oppose","option","orange","orbit","orchard","order","ordinary","organ","orient","original","orphan","ostrich","other","outdoor","outer","output","outside","oval","oven","over","own","owner","oxygen","oyster","ozone","pact","paddle","page","pair","palace","palm","panda","panel","panic","panther","paper","parade","parent","park","parrot","party","pass","patch","path","patient","patrol","pattern","pause","pave","payment","peace","peanut","pear","peasant","pelican","pen","penalty","pencil","people","pepper","perfect","permit","person","pet","phone","photo","phrase","physical","piano","picnic","picture","piece","pig","pigeon","pill","pilot","pink","pioneer","pipe","pistol","pitch","pizza","place","planet","plastic","plate","play","please","pledge","pluck","plug","plunge","poem","poet","point","polar","pole","police","pond","pony","pool","popular","portion","position","possible","post","potato","pottery","poverty","powder","power","practice","praise","predict","prefer","prepare","present","pretty","prevent","price","pride","primary","print","priority","prison","private","prize","problem","process","produce","profit","program","project","promote","proof","property","prosper","protect","proud","provide","public","pudding","pull","pulp","pulse","pumpkin","punch","pupil","puppy","purchase","purity","purpose","purse","push","put","puzzle","pyramid","quality","quantum","quarter","question","quick","quit","quiz","quote","rabbit","raccoon","race","rack","radar","radio","rail","rain","raise","rally","ramp","ranch","random","range","rapid","rare","rate","rather","raven","raw","razor","ready","real","reason","rebel","rebuild","recall","receive","recipe","record","recycle","reduce","reflect","reform","refuse","region","regret","regular","reject","relax","release","relief","rely","remain","remember","remind","remove","render","renew","rent","reopen","repair","repeat","replace","report","require","rescue","resemble","resist","resource","response","result","retire","retreat","return","reunion","reveal","review","reward","rhythm","rib","ribbon","rice","rich","ride","ridge","rifle","right","rigid","ring","riot","ripple","risk","ritual","rival","river","road","roast","robot","robust","rocket","romance","roof","rookie","room","rose","rotate","rough","round","route","royal","rubber","rude","rug","rule","run","runway","rural","sad","saddle","sadness","safe","sail","salad","salmon","salon","salt","salute","same","sample","sand","satisfy","satoshi","sauce","sausage","save","say","scale","scan","scare","scatter","scene","scheme","school","science","scissors","scorpion","scout","scrap","screen","script","scrub","sea","search","season","seat","second","secret","section","security","seed","seek","segment","select","sell","seminar","senior","sense","sentence","series","service","session","settle","setup","seven","shadow","shaft","shallow","share","shed","shell","sheriff","shield","shift","shine","ship","shiver","shock","shoe","shoot","shop","short","shoulder","shove","shrimp","shrug","shuffle","shy","sibling","sick","side","siege","sight","sign","silent","silk","silly","silver","similar","simple","since","sing","siren","sister","situate","six","size","skate","sketch","ski","skill","skin","skirt","skull","slab","slam","sleep","slender","slice","slide","slight","slim","slogan","slot","slow","slush","small","smart","smile","smoke","smooth","snack","snake","snap","sniff","snow","soap","soccer","social","sock","soda","soft","solar","soldier","solid","solution","solve","someone","song","soon","sorry","sort","soul","sound","soup","source","south","space","spare","spatial","spawn","speak","special","speed","spell","spend","sphere","spice","spider","spike","spin","spirit","split","spoil","sponsor","spoon","sport","spot","spray","spread","spring","spy","square","squeeze","squirrel","stable","stadium","staff","stage","stairs","stamp","stand","start","state","stay","steak","steel","stem","step","stereo","stick","still","sting","stock","stomach","stone","stool","story","stove","strategy","street","strike","strong","struggle","student","stuff","stumble","style","subject","submit","subway","success","such","sudden","suffer","sugar","suggest","suit","summer","sun","sunny","sunset","super","supply","supreme","sure","surface","surge","surprise","surround","survey","suspect","sustain","swallow","swamp","swap","swarm","swear","sweet","swift","swim","swing","switch","sword","symbol","symptom","syrup","system","table","tackle","tag","tail","talent","talk","tank","tape","target","task","taste","tattoo","taxi","teach","team","tell","ten","tenant","tennis","tent","term","test","text","thank","that","theme","then","theory","there","they","thing","this","thought","three","thrive","throw","thumb","thunder","ticket","tide","tiger","tilt","timber","time","tiny","tip","tired","tissue","title","toast","tobacco","today","toddler","toe","together","toilet","token","tomato","tomorrow","tone","tongue","tonight","tool","tooth","top","topic","topple","torch","tornado","tortoise","toss","total","tourist","toward","tower","town","toy","track","trade","traffic","tragic","train","transfer","trap","trash","travel","tray","treat","tree","trend","trial","tribe","trick","trigger","trim","trip","trophy","trouble","truck","true","truly","trumpet","trust","truth","try","tube","tuition","tumble","tuna","tunnel","turkey","turn","turtle","twelve","twenty","twice","twin","twist","two","type","typical","ugly","umbrella","unable","unaware","uncle","uncover","under","undo","unfair","unfold","unhappy","uniform","unique","unit","universe","unknown","unlock","until","unusual","unveil","update","upgrade","uphold","upon","upper","upset","urban","urge","usage","use","used","useful","useless","usual","utility","vacant","vacuum","vague","valid","valley","valve","van","vanish","vapor","various","vast","vault","vehicle","velvet","vendor","venture","venue","verb","verify","version","very","vessel","veteran","viable","vibrant","vicious","victory","video","view","village","vintage","violin","virtual","virus","visa","visit","visual","vital","vivid","vocal","voice","void","volcano","volume","vote","voyage","wage","wagon","wait","walk","wall","walnut","want","warfare","warm","warrior","wash","wasp","waste","water","wave","way","wealth","weapon","wear","weasel","weather","web","wedding","weekend","weird","welcome","west","wet","whale","what","wheat","wheel","when","where","whip","whisper","wide","width","wife","wild","will","win","window","wine","wing","wink","winner","winter","wire","wisdom","wise","wish","witness","wolf","woman","wonder","wood","wool","word","work","world","worry","worth","wrap","wreck","wrestle","wrist","write","wrong","yard","year","yellow","you","young","youth","zebra","zero","zone","zoo"];t.exports=i},{}],6:[function(e,t,r){t.exports={CHINESE:e("./chinese"),ENGLISH:e("./english"),JAPANESE:e("./japanese"),SPANISH:e("./spanish")}},{"./chinese":4,"./english":5,"./japanese":7,"./spanish":8}],7:[function(e,t,r){"use strict";var i=["あいこくしん","あいさつ","あいだ","あおぞら","あかちゃん","あきる","あけがた","あける","あこがれる","あさい","あさひ","あしあと","あじわう","あずかる","あずき","あそぶ","あたえる","あたためる","あたりまえ","あたる","あつい","あつかう","あっしゅく","あつまり","あつめる","あてな","あてはまる","あひる","あぶら","あぶる","あふれる","あまい","あまど","あまやかす","あまり","あみもの","あめりか","あやまる","あゆむ","あらいぐま","あらし","あらすじ","あらためる","あらゆる","あらわす","ありがとう","あわせる","あわてる","あんい","あんがい","あんこ","あんぜん","あんてい","あんない","あんまり","いいだす","いおん","いがい","いがく","いきおい","いきなり","いきもの","いきる","いくじ","いくぶん","いけばな","いけん","いこう","いこく","いこつ","いさましい","いさん","いしき","いじゅう","いじょう","いじわる","いずみ","いずれ","いせい","いせえび","いせかい","いせき","いぜん","いそうろう","いそがしい","いだい","いだく","いたずら","いたみ","いたりあ","いちおう","いちじ","いちど","いちば","いちぶ","いちりゅう","いつか","いっしゅん","いっせい","いっそう","いったん","いっち","いってい","いっぽう","いてざ","いてん","いどう","いとこ","いない","いなか","いねむり","いのち","いのる","いはつ","いばる","いはん","いびき","いひん","いふく","いへん","いほう","いみん","いもうと","いもたれ","いもり","いやがる","いやす","いよかん","いよく","いらい","いらすと","いりぐち","いりょう","いれい","いれもの","いれる","いろえんぴつ","いわい","いわう","いわかん","いわば","いわゆる","いんげんまめ","いんさつ","いんしょう","いんよう","うえき","うえる","うおざ","うがい","うかぶ","うかべる","うきわ","うくらいな","うくれれ","うけたまわる","うけつけ","うけとる","うけもつ","うける","うごかす","うごく","うこん","うさぎ","うしなう","うしろがみ","うすい","うすぎ","うすぐらい","うすめる","うせつ","うちあわせ","うちがわ","うちき","うちゅう","うっかり","うつくしい","うったえる","うつる","うどん","うなぎ","うなじ","うなずく","うなる","うねる","うのう","うぶげ","うぶごえ","うまれる","うめる","うもう","うやまう","うよく","うらがえす","うらぐち","うらない","うりあげ","うりきれ","うるさい","うれしい","うれゆき","うれる","うろこ","うわき","うわさ","うんこう","うんちん","うんてん","うんどう","えいえん","えいが","えいきょう","えいご","えいせい","えいぶん","えいよう","えいわ","えおり","えがお","えがく","えきたい","えくせる","えしゃく","えすて","えつらん","えのぐ","えほうまき","えほん","えまき","えもじ","えもの","えらい","えらぶ","えりあ","えんえん","えんかい","えんぎ","えんげき","えんしゅう","えんぜつ","えんそく","えんちょう","えんとつ","おいかける","おいこす","おいしい","おいつく","おうえん","おうさま","おうじ","おうせつ","おうたい","おうふく","おうべい","おうよう","おえる","おおい","おおう","おおどおり","おおや","おおよそ","おかえり","おかず","おがむ","おかわり","おぎなう","おきる","おくさま","おくじょう","おくりがな","おくる","おくれる","おこす","おこなう","おこる","おさえる","おさない","おさめる","おしいれ","おしえる","おじぎ","おじさん","おしゃれ","おそらく","おそわる","おたがい","おたく","おだやか","おちつく","おっと","おつり","おでかけ","おとしもの","おとなしい","おどり","おどろかす","おばさん","おまいり","おめでとう","おもいで","おもう","おもたい","おもちゃ","おやつ","おやゆび","およぼす","おらんだ","おろす","おんがく","おんけい","おんしゃ","おんせん","おんだん","おんちゅう","おんどけい","かあつ","かいが","がいき","がいけん","がいこう","かいさつ","かいしゃ","かいすいよく","かいぜん","かいぞうど","かいつう","かいてん","かいとう","かいふく","がいへき","かいほう","かいよう","がいらい","かいわ","かえる","かおり","かかえる","かがく","かがし","かがみ","かくご","かくとく","かざる","がぞう","かたい","かたち","がちょう","がっきゅう","がっこう","がっさん","がっしょう","かなざわし","かのう","がはく","かぶか","かほう","かほご","かまう","かまぼこ","かめれおん","かゆい","かようび","からい","かるい","かろう","かわく","かわら","がんか","かんけい","かんこう","かんしゃ","かんそう","かんたん","かんち","がんばる","きあい","きあつ","きいろ","ぎいん","きうい","きうん","きえる","きおう","きおく","きおち","きおん","きかい","きかく","きかんしゃ","ききて","きくばり","きくらげ","きけんせい","きこう","きこえる","きこく","きさい","きさく","きさま","きさらぎ","ぎじかがく","ぎしき","ぎじたいけん","ぎじにってい","ぎじゅつしゃ","きすう","きせい","きせき","きせつ","きそう","きぞく","きぞん","きたえる","きちょう","きつえん","ぎっちり","きつつき","きつね","きてい","きどう","きどく","きない","きなが","きなこ","きぬごし","きねん","きのう","きのした","きはく","きびしい","きひん","きふく","きぶん","きぼう","きほん","きまる","きみつ","きむずかしい","きめる","きもだめし","きもち","きもの","きゃく","きやく","ぎゅうにく","きよう","きょうりゅう","きらい","きらく","きりん","きれい","きれつ","きろく","ぎろん","きわめる","ぎんいろ","きんかくじ","きんじょ","きんようび","ぐあい","くいず","くうかん","くうき","くうぐん","くうこう","ぐうせい","くうそう","ぐうたら","くうふく","くうぼ","くかん","くきょう","くげん","ぐこう","くさい","くさき","くさばな","くさる","くしゃみ","くしょう","くすのき","くすりゆび","くせげ","くせん","ぐたいてき","くださる","くたびれる","くちこみ","くちさき","くつした","ぐっすり","くつろぐ","くとうてん","くどく","くなん","くねくね","くのう","くふう","くみあわせ","くみたてる","くめる","くやくしょ","くらす","くらべる","くるま","くれる","くろう","くわしい","ぐんかん","ぐんしょく","ぐんたい","ぐんて","けあな","けいかく","けいけん","けいこ","けいさつ","げいじゅつ","けいたい","げいのうじん","けいれき","けいろ","けおとす","けおりもの","げきか","げきげん","げきだん","げきちん","げきとつ","げきは","げきやく","げこう","げこくじょう","げざい","けさき","げざん","けしき","けしごむ","けしょう","げすと","けたば","けちゃっぷ","けちらす","けつあつ","けつい","けつえき","けっこん","けつじょ","けっせき","けってい","けつまつ","げつようび","げつれい","けつろん","げどく","けとばす","けとる","けなげ","けなす","けなみ","けぬき","げねつ","けねん","けはい","げひん","けぶかい","げぼく","けまり","けみかる","けむし","けむり","けもの","けらい","けろけろ","けわしい","けんい","けんえつ","けんお","けんか","げんき","けんげん","けんこう","けんさく","けんしゅう","けんすう","げんそう","けんちく","けんてい","けんとう","けんない","けんにん","げんぶつ","けんま","けんみん","けんめい","けんらん","けんり","こあくま","こいぬ","こいびと","ごうい","こうえん","こうおん","こうかん","ごうきゅう","ごうけい","こうこう","こうさい","こうじ","こうすい","ごうせい","こうそく","こうたい","こうちゃ","こうつう","こうてい","こうどう","こうない","こうはい","ごうほう","ごうまん","こうもく","こうりつ","こえる","こおり","ごかい","ごがつ","ごかん","こくご","こくさい","こくとう","こくない","こくはく","こぐま","こけい","こける","ここのか","こころ","こさめ","こしつ","こすう","こせい","こせき","こぜん","こそだて","こたい","こたえる","こたつ","こちょう","こっか","こつこつ","こつばん","こつぶ","こてい","こてん","ことがら","ことし","ことば","ことり","こなごな","こねこね","このまま","このみ","このよ","ごはん","こひつじ","こふう","こふん","こぼれる","ごまあぶら","こまかい","ごますり","こまつな","こまる","こむぎこ","こもじ","こもち","こもの","こもん","こやく","こやま","こゆう","こゆび","こよい","こよう","こりる","これくしょん","ころっけ","こわもて","こわれる","こんいん","こんかい","こんき","こんしゅう","こんすい","こんだて","こんとん","こんなん","こんびに","こんぽん","こんまけ","こんや","こんれい","こんわく","ざいえき","さいかい","さいきん","ざいげん","ざいこ","さいしょ","さいせい","ざいたく","ざいちゅう","さいてき","ざいりょう","さうな","さかいし","さがす","さかな","さかみち","さがる","さぎょう","さくし","さくひん","さくら","さこく","さこつ","さずかる","ざせき","さたん","さつえい","ざつおん","ざっか","ざつがく","さっきょく","ざっし","さつじん","ざっそう","さつたば","さつまいも","さてい","さといも","さとう","さとおや","さとし","さとる","さのう","さばく","さびしい","さべつ","さほう","さほど","さます","さみしい","さみだれ","さむけ","さめる","さやえんどう","さゆう","さよう","さよく","さらだ","ざるそば","さわやか","さわる","さんいん","さんか","さんきゃく","さんこう","さんさい","ざんしょ","さんすう","さんせい","さんそ","さんち","さんま","さんみ","さんらん","しあい","しあげ","しあさって","しあわせ","しいく","しいん","しうち","しえい","しおけ","しかい","しかく","じかん","しごと","しすう","じだい","したうけ","したぎ","したて","したみ","しちょう","しちりん","しっかり","しつじ","しつもん","してい","してき","してつ","じてん","じどう","しなぎれ","しなもの","しなん","しねま","しねん","しのぐ","しのぶ","しはい","しばかり","しはつ","しはらい","しはん","しひょう","しふく","じぶん","しへい","しほう","しほん","しまう","しまる","しみん","しむける","じむしょ","しめい","しめる","しもん","しゃいん","しゃうん","しゃおん","じゃがいも","しやくしょ","しゃくほう","しゃけん","しゃこ","しゃざい","しゃしん","しゃせん","しゃそう","しゃたい","しゃちょう","しゃっきん","じゃま","しゃりん","しゃれい","じゆう","じゅうしょ","しゅくはく","じゅしん","しゅっせき","しゅみ","しゅらば","じゅんばん","しょうかい","しょくたく","しょっけん","しょどう","しょもつ","しらせる","しらべる","しんか","しんこう","じんじゃ","しんせいじ","しんちく","しんりん","すあげ","すあし","すあな","ずあん","すいえい","すいか","すいとう","ずいぶん","すいようび","すうがく","すうじつ","すうせん","すおどり","すきま","すくう","すくない","すける","すごい","すこし","ずさん","すずしい","すすむ","すすめる","すっかり","ずっしり","ずっと","すてき","すてる","すねる","すのこ","すはだ","すばらしい","ずひょう","ずぶぬれ","すぶり","すふれ","すべて","すべる","ずほう","すぼん","すまい","すめし","すもう","すやき","すらすら","するめ","すれちがう","すろっと","すわる","すんぜん","すんぽう","せあぶら","せいかつ","せいげん","せいじ","せいよう","せおう","せかいかん","せきにん","せきむ","せきゆ","せきらんうん","せけん","せこう","せすじ","せたい","せたけ","せっかく","せっきゃく","ぜっく","せっけん","せっこつ","せっさたくま","せつぞく","せつだん","せつでん","せっぱん","せつび","せつぶん","せつめい","せつりつ","せなか","せのび","せはば","せびろ","せぼね","せまい","せまる","せめる","せもたれ","せりふ","ぜんあく","せんい","せんえい","せんか","せんきょ","せんく","せんげん","ぜんご","せんさい","せんしゅ","せんすい","せんせい","せんぞ","せんたく","せんちょう","せんてい","せんとう","せんぬき","せんねん","せんぱい","ぜんぶ","ぜんぽう","せんむ","せんめんじょ","せんもん","せんやく","せんゆう","せんよう","ぜんら","ぜんりゃく","せんれい","せんろ","そあく","そいとげる","そいね","そうがんきょう","そうき","そうご","そうしん","そうだん","そうなん","そうび","そうめん","そうり","そえもの","そえん","そがい","そげき","そこう","そこそこ","そざい","そしな","そせい","そせん","そそぐ","そだてる","そつう","そつえん","そっかん","そつぎょう","そっけつ","そっこう","そっせん","そっと","そとがわ","そとづら","そなえる","そなた","そふぼ","そぼく","そぼろ","そまつ","そまる","そむく","そむりえ","そめる","そもそも","そよかぜ","そらまめ","そろう","そんかい","そんけい","そんざい","そんしつ","そんぞく","そんちょう","ぞんび","ぞんぶん","そんみん","たあい","たいいん","たいうん","たいえき","たいおう","だいがく","たいき","たいぐう","たいけん","たいこ","たいざい","だいじょうぶ","だいすき","たいせつ","たいそう","だいたい","たいちょう","たいてい","だいどころ","たいない","たいねつ","たいのう","たいはん","だいひょう","たいふう","たいへん","たいほ","たいまつばな","たいみんぐ","たいむ","たいめん","たいやき","たいよう","たいら","たいりょく","たいる","たいわん","たうえ","たえる","たおす","たおる","たおれる","たかい","たかね","たきび","たくさん","たこく","たこやき","たさい","たしざん","だじゃれ","たすける","たずさわる","たそがれ","たたかう","たたく","ただしい","たたみ","たちばな","だっかい","だっきゃく","だっこ","だっしゅつ","だったい","たてる","たとえる","たなばた","たにん","たぬき","たのしみ","たはつ","たぶん","たべる","たぼう","たまご","たまる","だむる","ためいき","ためす","ためる","たもつ","たやすい","たよる","たらす","たりきほんがん","たりょう","たりる","たると","たれる","たれんと","たろっと","たわむれる","だんあつ","たんい","たんおん","たんか","たんき","たんけん","たんご","たんさん","たんじょうび","だんせい","たんそく","たんたい","だんち","たんてい","たんとう","だんな","たんにん","だんねつ","たんのう","たんぴん","だんぼう","たんまつ","たんめい","だんれつ","だんろ","だんわ","ちあい","ちあん","ちいき","ちいさい","ちえん","ちかい","ちから","ちきゅう","ちきん","ちけいず","ちけん","ちこく","ちさい","ちしき","ちしりょう","ちせい","ちそう","ちたい","ちたん","ちちおや","ちつじょ","ちてき","ちてん","ちぬき","ちぬり","ちのう","ちひょう","ちへいせん","ちほう","ちまた","ちみつ","ちみどろ","ちめいど","ちゃんこなべ","ちゅうい","ちゆりょく","ちょうし","ちょさくけん","ちらし","ちらみ","ちりがみ","ちりょう","ちるど","ちわわ","ちんたい","ちんもく","ついか","ついたち","つうか","つうじょう","つうはん","つうわ","つかう","つかれる","つくね","つくる","つけね","つける","つごう","つたえる","つづく","つつじ","つつむ","つとめる","つながる","つなみ","つねづね","つのる","つぶす","つまらない","つまる","つみき","つめたい","つもり","つもる","つよい","つるぼ","つるみく","つわもの","つわり","てあし","てあて","てあみ","ていおん","ていか","ていき","ていけい","ていこく","ていさつ","ていし","ていせい","ていたい","ていど","ていねい","ていひょう","ていへん","ていぼう","てうち","ておくれ","てきとう","てくび","でこぼこ","てさぎょう","てさげ","てすり","てそう","てちがい","てちょう","てつがく","てつづき","でっぱ","てつぼう","てつや","でぬかえ","てぬき","てぬぐい","てのひら","てはい","てぶくろ","てふだ","てほどき","てほん","てまえ","てまきずし","てみじか","てみやげ","てらす","てれび","てわけ","てわたし","でんあつ","てんいん","てんかい","てんき","てんぐ","てんけん","てんごく","てんさい","てんし","てんすう","でんち","てんてき","てんとう","てんない","てんぷら","てんぼうだい","てんめつ","てんらんかい","でんりょく","でんわ","どあい","といれ","どうかん","とうきゅう","どうぐ","とうし","とうむぎ","とおい","とおか","とおく","とおす","とおる","とかい","とかす","ときおり","ときどき","とくい","とくしゅう","とくてん","とくに","とくべつ","とけい","とける","とこや","とさか","としょかん","とそう","とたん","とちゅう","とっきゅう","とっくん","とつぜん","とつにゅう","とどける","ととのえる","とない","となえる","となり","とのさま","とばす","どぶがわ","とほう","とまる","とめる","ともだち","ともる","どようび","とらえる","とんかつ","どんぶり","ないかく","ないこう","ないしょ","ないす","ないせん","ないそう","なおす","ながい","なくす","なげる","なこうど","なさけ","なたでここ","なっとう","なつやすみ","ななおし","なにごと","なにもの","なにわ","なのか","なふだ","なまいき","なまえ","なまみ","なみだ","なめらか","なめる","なやむ","ならう","ならび","ならぶ","なれる","なわとび","なわばり","にあう","にいがた","にうけ","におい","にかい","にがて","にきび","にくしみ","にくまん","にげる","にさんかたんそ","にしき","にせもの","にちじょう","にちようび","にっか","にっき","にっけい","にっこう","にっさん","にっしょく","にっすう","にっせき","にってい","になう","にほん","にまめ","にもつ","にやり","にゅういん","にりんしゃ","にわとり","にんい","にんか","にんき","にんげん","にんしき","にんずう","にんそう","にんたい","にんち","にんてい","にんにく","にんぷ","にんまり","にんむ","にんめい","にんよう","ぬいくぎ","ぬかす","ぬぐいとる","ぬぐう","ぬくもり","ぬすむ","ぬまえび","ぬめり","ぬらす","ぬんちゃく","ねあげ","ねいき","ねいる","ねいろ","ねぐせ","ねくたい","ねくら","ねこぜ","ねこむ","ねさげ","ねすごす","ねそべる","ねだん","ねつい","ねっしん","ねつぞう","ねったいぎょ","ねぶそく","ねふだ","ねぼう","ねほりはほり","ねまき","ねまわし","ねみみ","ねむい","ねむたい","ねもと","ねらう","ねわざ","ねんいり","ねんおし","ねんかん","ねんきん","ねんぐ","ねんざ","ねんし","ねんちゃく","ねんど","ねんぴ","ねんぶつ","ねんまつ","ねんりょう","ねんれい","のいず","のおづま","のがす","のきなみ","のこぎり","のこす","のこる","のせる","のぞく","のぞむ","のたまう","のちほど","のっく","のばす","のはら","のべる","のぼる","のみもの","のやま","のらいぬ","のらねこ","のりもの","のりゆき","のれん","のんき","ばあい","はあく","ばあさん","ばいか","ばいく","はいけん","はいご","はいしん","はいすい","はいせん","はいそう","はいち","ばいばい","はいれつ","はえる","はおる","はかい","ばかり","はかる","はくしゅ","はけん","はこぶ","はさみ","はさん","はしご","ばしょ","はしる","はせる","ぱそこん","はそん","はたん","はちみつ","はつおん","はっかく","はづき","はっきり","はっくつ","はっけん","はっこう","はっさん","はっしん","はったつ","はっちゅう","はってん","はっぴょう","はっぽう","はなす","はなび","はにかむ","はぶらし","はみがき","はむかう","はめつ","はやい","はやし","はらう","はろうぃん","はわい","はんい","はんえい","はんおん","はんかく","はんきょう","ばんぐみ","はんこ","はんしゃ","はんすう","はんだん","ぱんち","ぱんつ","はんてい","はんとし","はんのう","はんぱ","はんぶん","はんぺん","はんぼうき","はんめい","はんらん","はんろん","ひいき","ひうん","ひえる","ひかく","ひかり","ひかる","ひかん","ひくい","ひけつ","ひこうき","ひこく","ひさい","ひさしぶり","ひさん","びじゅつかん","ひしょ","ひそか","ひそむ","ひたむき","ひだり","ひたる","ひつぎ","ひっこし","ひっし","ひつじゅひん","ひっす","ひつぜん","ぴったり","ぴっちり","ひつよう","ひてい","ひとごみ","ひなまつり","ひなん","ひねる","ひはん","ひびく","ひひょう","ひほう","ひまわり","ひまん","ひみつ","ひめい","ひめじし","ひやけ","ひやす","ひよう","びょうき","ひらがな","ひらく","ひりつ","ひりょう","ひるま","ひるやすみ","ひれい","ひろい","ひろう","ひろき","ひろゆき","ひんかく","ひんけつ","ひんこん","ひんしゅ","ひんそう","ぴんち","ひんぱん","びんぼう","ふあん","ふいうち","ふうけい","ふうせん","ぷうたろう","ふうとう","ふうふ","ふえる","ふおん","ふかい","ふきん","ふくざつ","ふくぶくろ","ふこう","ふさい","ふしぎ","ふじみ","ふすま","ふせい","ふせぐ","ふそく","ぶたにく","ふたん","ふちょう","ふつう","ふつか","ふっかつ","ふっき","ふっこく","ぶどう","ふとる","ふとん","ふのう","ふはい","ふひょう","ふへん","ふまん","ふみん","ふめつ","ふめん","ふよう","ふりこ","ふりる","ふるい","ふんいき","ぶんがく","ぶんぐ","ふんしつ","ぶんせき","ふんそう","ぶんぽう","へいあん","へいおん","へいがい","へいき","へいげん","へいこう","へいさ","へいしゃ","へいせつ","へいそ","へいたく","へいてん","へいねつ","へいわ","へきが","へこむ","べにいろ","べにしょうが","へらす","へんかん","べんきょう","べんごし","へんさい","へんたい","べんり","ほあん","ほいく","ぼうぎょ","ほうこく","ほうそう","ほうほう","ほうもん","ほうりつ","ほえる","ほおん","ほかん","ほきょう","ぼきん","ほくろ","ほけつ","ほけん","ほこう","ほこる","ほしい","ほしつ","ほしゅ","ほしょう","ほせい","ほそい","ほそく","ほたて","ほたる","ぽちぶくろ","ほっきょく","ほっさ","ほったん","ほとんど","ほめる","ほんい","ほんき","ほんけ","ほんしつ","ほんやく","まいにち","まかい","まかせる","まがる","まける","まこと","まさつ","まじめ","ますく","まぜる","まつり","まとめ","まなぶ","まぬけ","まねく","まほう","まもる","まゆげ","まよう","まろやか","まわす","まわり","まわる","まんが","まんきつ","まんぞく","まんなか","みいら","みうち","みえる","みがく","みかた","みかん","みけん","みこん","みじかい","みすい","みすえる","みせる","みっか","みつかる","みつける","みてい","みとめる","みなと","みなみかさい","みねらる","みのう","みのがす","みほん","みもと","みやげ","みらい","みりょく","みわく","みんか","みんぞく","むいか","むえき","むえん","むかい","むかう","むかえ","むかし","むぎちゃ","むける","むげん","むさぼる","むしあつい","むしば","むじゅん","むしろ","むすう","むすこ","むすぶ","むすめ","むせる","むせん","むちゅう","むなしい","むのう","むやみ","むよう","むらさき","むりょう","むろん","めいあん","めいうん","めいえん","めいかく","めいきょく","めいさい","めいし","めいそう","めいぶつ","めいれい","めいわく","めぐまれる","めざす","めした","めずらしい","めだつ","めまい","めやす","めんきょ","めんせき","めんどう","もうしあげる","もうどうけん","もえる","もくし","もくてき","もくようび","もちろん","もどる","もらう","もんく","もんだい","やおや","やける","やさい","やさしい","やすい","やすたろう","やすみ","やせる","やそう","やたい","やちん","やっと","やっぱり","やぶる","やめる","ややこしい","やよい","やわらかい","ゆうき","ゆうびんきょく","ゆうべ","ゆうめい","ゆけつ","ゆしゅつ","ゆせん","ゆそう","ゆたか","ゆちゃく","ゆでる","ゆにゅう","ゆびわ","ゆらい","ゆれる","ようい","ようか","ようきゅう","ようじ","ようす","ようちえん","よかぜ","よかん","よきん","よくせい","よくぼう","よけい","よごれる","よさん","よしゅう","よそう","よそく","よっか","よてい","よどがわく","よねつ","よやく","よゆう","よろこぶ","よろしい","らいう","らくがき","らくご","らくさつ","らくだ","らしんばん","らせん","らぞく","らたい","らっか","られつ","りえき","りかい","りきさく","りきせつ","りくぐん","りくつ","りけん","りこう","りせい","りそう","りそく","りてん","りねん","りゆう","りゅうがく","りよう","りょうり","りょかん","りょくちゃ","りょこう","りりく","りれき","りろん","りんご","るいけい","るいさい","るいじ","るいせき","るすばん","るりがわら","れいかん","れいぎ","れいせい","れいぞうこ","れいとう","れいぼう","れきし","れきだい","れんあい","れんけい","れんこん","れんさい","れんしゅう","れんぞく","れんらく","ろうか","ろうご","ろうじん","ろうそく","ろくが","ろこつ","ろじうら","ろしゅつ","ろせん","ろてん","ろめん","ろれつ","ろんぎ","ろんぱ","ろんぶん","ろんり","わかす","わかめ","わかやま","わかれる","わしつ","わじまし","わすれもの","わらう","われる"];

t.exports=i},{}],8:[function(e,t,r){"use strict";var i=["ábaco","abdomen","abeja","abierto","abogado","abono","aborto","abrazo","abrir","abuelo","abuso","acabar","academia","acceso","acción","aceite","acelga","acento","aceptar","ácido","aclarar","acné","acoger","acoso","activo","acto","actriz","actuar","acudir","acuerdo","acusar","adicto","admitir","adoptar","adorno","aduana","adulto","aéreo","afectar","afición","afinar","afirmar","ágil","agitar","agonía","agosto","agotar","agregar","agrio","agua","agudo","águila","aguja","ahogo","ahorro","aire","aislar","ajedrez","ajeno","ajuste","alacrán","alambre","alarma","alba","álbum","alcalde","aldea","alegre","alejar","alerta","aleta","alfiler","alga","algodón","aliado","aliento","alivio","alma","almeja","almíbar","altar","alteza","altivo","alto","altura","alumno","alzar","amable","amante","amapola","amargo","amasar","ámbar","ámbito","ameno","amigo","amistad","amor","amparo","amplio","ancho","anciano","ancla","andar","andén","anemia","ángulo","anillo","ánimo","anís","anotar","antena","antiguo","antojo","anual","anular","anuncio","añadir","añejo","año","apagar","aparato","apetito","apio","aplicar","apodo","aporte","apoyo","aprender","aprobar","apuesta","apuro","arado","araña","arar","árbitro","árbol","arbusto","archivo","arco","arder","ardilla","arduo","área","árido","aries","armonía","arnés","aroma","arpa","arpón","arreglo","arroz","arruga","arte","artista","asa","asado","asalto","ascenso","asegurar","aseo","asesor","asiento","asilo","asistir","asno","asombro","áspero","astilla","astro","astuto","asumir","asunto","atajo","ataque","atar","atento","ateo","ático","atleta","átomo","atraer","atroz","atún","audaz","audio","auge","aula","aumento","ausente","autor","aval","avance","avaro","ave","avellana","avena","avestruz","avión","aviso","ayer","ayuda","ayuno","azafrán","azar","azote","azúcar","azufre","azul","baba","babor","bache","bahía","baile","bajar","balanza","balcón","balde","bambú","banco","banda","baño","barba","barco","barniz","barro","báscula","bastón","basura","batalla","batería","batir","batuta","baúl","bazar","bebé","bebida","bello","besar","beso","bestia","bicho","bien","bingo","blanco","bloque","blusa","boa","bobina","bobo","boca","bocina","boda","bodega","boina","bola","bolero","bolsa","bomba","bondad","bonito","bono","bonsái","borde","borrar","bosque","bote","botín","bóveda","bozal","bravo","brazo","brecha","breve","brillo","brinco","brisa","broca","broma","bronce","brote","bruja","brusco","bruto","buceo","bucle","bueno","buey","bufanda","bufón","búho","buitre","bulto","burbuja","burla","burro","buscar","butaca","buzón","caballo","cabeza","cabina","cabra","cacao","cadáver","cadena","caer","café","caída","caimán","caja","cajón","cal","calamar","calcio","caldo","calidad","calle","calma","calor","calvo","cama","cambio","camello","camino","campo","cáncer","candil","canela","canguro","canica","canto","caña","cañón","caoba","caos","capaz","capitán","capote","captar","capucha","cara","carbón","cárcel","careta","carga","cariño","carne","carpeta","carro","carta","casa","casco","casero","caspa","castor","catorce","catre","caudal","causa","cazo","cebolla","ceder","cedro","celda","célebre","celoso","célula","cemento","ceniza","centro","cerca","cerdo","cereza","cero","cerrar","certeza","césped","cetro","chacal","chaleco","champú","chancla","chapa","charla","chico","chiste","chivo","choque","choza","chuleta","chupar","ciclón","ciego","cielo","cien","cierto","cifra","cigarro","cima","cinco","cine","cinta","ciprés","circo","ciruela","cisne","cita","ciudad","clamor","clan","claro","clase","clave","cliente","clima","clínica","cobre","cocción","cochino","cocina","coco","código","codo","cofre","coger","cohete","cojín","cojo","cola","colcha","colegio","colgar","colina","collar","colmo","columna","combate","comer","comida","cómodo","compra","conde","conejo","conga","conocer","consejo","contar","copa","copia","corazón","corbata","corcho","cordón","corona","correr","coser","cosmos","costa","cráneo","cráter","crear","crecer","creído","crema","cría","crimen","cripta","crisis","cromo","crónica","croqueta","crudo","cruz","cuadro","cuarto","cuatro","cubo","cubrir","cuchara","cuello","cuento","cuerda","cuesta","cueva","cuidar","culebra","culpa","culto","cumbre","cumplir","cuna","cuneta","cuota","cupón","cúpula","curar","curioso","curso","curva","cutis","dama","danza","dar","dardo","dátil","deber","débil","década","decir","dedo","defensa","definir","dejar","delfín","delgado","delito","demora","denso","dental","deporte","derecho","derrota","desayuno","deseo","desfile","desnudo","destino","desvío","detalle","detener","deuda","día","diablo","diadema","diamante","diana","diario","dibujo","dictar","diente","dieta","diez","difícil","digno","dilema","diluir","dinero","directo","dirigir","disco","diseño","disfraz","diva","divino","doble","doce","dolor","domingo","don","donar","dorado","dormir","dorso","dos","dosis","dragón","droga","ducha","duda","duelo","dueño","dulce","dúo","duque","durar","dureza","duro","ébano","ebrio","echar","eco","ecuador","edad","edición","edificio","editor","educar","efecto","eficaz","eje","ejemplo","elefante","elegir","elemento","elevar","elipse","élite","elixir","elogio","eludir","embudo","emitir","emoción","empate","empeño","empleo","empresa","enano","encargo","enchufe","encía","enemigo","enero","enfado","enfermo","engaño","enigma","enlace","enorme","enredo","ensayo","enseñar","entero","entrar","envase","envío","época","equipo","erizo","escala","escena","escolar","escribir","escudo","esencia","esfera","esfuerzo","espada","espejo","espía","esposa","espuma","esquí","estar","este","estilo","estufa","etapa","eterno","ética","etnia","evadir","evaluar","evento","evitar","exacto","examen","exceso","excusa","exento","exigir","exilio","existir","éxito","experto","explicar","exponer","extremo","fábrica","fábula","fachada","fácil","factor","faena","faja","falda","fallo","falso","faltar","fama","familia","famoso","faraón","farmacia","farol","farsa","fase","fatiga","fauna","favor","fax","febrero","fecha","feliz","feo","feria","feroz","fértil","fervor","festín","fiable","fianza","fiar","fibra","ficción","ficha","fideo","fiebre","fiel","fiera","fiesta","figura","fijar","fijo","fila","filete","filial","filtro","fin","finca","fingir","finito","firma","flaco","flauta","flecha","flor","flota","fluir","flujo","flúor","fobia","foca","fogata","fogón","folio","folleto","fondo","forma","forro","fortuna","forzar","fosa","foto","fracaso","frágil","franja","frase","fraude","freír","freno","fresa","frío","frito","fruta","fuego","fuente","fuerza","fuga","fumar","función","funda","furgón","furia","fusil","fútbol","futuro","gacela","gafas","gaita","gajo","gala","galería","gallo","gamba","ganar","gancho","ganga","ganso","garaje","garza","gasolina","gastar","gato","gavilán","gemelo","gemir","gen","género","genio","gente","geranio","gerente","germen","gesto","gigante","gimnasio","girar","giro","glaciar","globo","gloria","gol","golfo","goloso","golpe","goma","gordo","gorila","gorra","gota","goteo","gozar","grada","gráfico","grano","grasa","gratis","grave","grieta","grillo","gripe","gris","grito","grosor","grúa","grueso","grumo","grupo","guante","guapo","guardia","guerra","guía","guiño","guion","guiso","guitarra","gusano","gustar","haber","hábil","hablar","hacer","hacha","hada","hallar","hamaca","harina","haz","hazaña","hebilla","hebra","hecho","helado","helio","hembra","herir","hermano","héroe","hervir","hielo","hierro","hígado","higiene","hijo","himno","historia","hocico","hogar","hoguera","hoja","hombre","hongo","honor","honra","hora","hormiga","horno","hostil","hoyo","hueco","huelga","huerta","hueso","huevo","huida","huir","humano","húmedo","humilde","humo","hundir","huracán","hurto","icono","ideal","idioma","ídolo","iglesia","iglú","igual","ilegal","ilusión","imagen","imán","imitar","impar","imperio","imponer","impulso","incapaz","índice","inerte","infiel","informe","ingenio","inicio","inmenso","inmune","innato","insecto","instante","interés","íntimo","intuir","inútil","invierno","ira","iris","ironía","isla","islote","jabalí","jabón","jamón","jarabe","jardín","jarra","jaula","jazmín","jefe","jeringa","jinete","jornada","joroba","joven","joya","juerga","jueves","juez","jugador","jugo","juguete","juicio","junco","jungla","junio","juntar","júpiter","jurar","justo","juvenil","juzgar","kilo","koala","labio","lacio","lacra","lado","ladrón","lagarto","lágrima","laguna","laico","lamer","lámina","lámpara","lana","lancha","langosta","lanza","lápiz","largo","larva","lástima","lata","látex","latir","laurel","lavar","lazo","leal","lección","leche","lector","leer","legión","legumbre","lejano","lengua","lento","leña","león","leopardo","lesión","letal","letra","leve","leyenda","libertad","libro","licor","líder","lidiar","lienzo","liga","ligero","lima","límite","limón","limpio","lince","lindo","línea","lingote","lino","linterna","líquido","liso","lista","litera","litio","litro","llaga","llama","llanto","llave","llegar","llenar","llevar","llorar","llover","lluvia","lobo","loción","loco","locura","lógica","logro","lombriz","lomo","lonja","lote","lucha","lucir","lugar","lujo","luna","lunes","lupa","lustro","luto","luz","maceta","macho","madera","madre","maduro","maestro","mafia","magia","mago","maíz","maldad","maleta","malla","malo","mamá","mambo","mamut","manco","mando","manejar","manga","maniquí","manjar","mano","manso","manta","mañana","mapa","máquina","mar","marco","marea","marfil","margen","marido","mármol","marrón","martes","marzo","masa","máscara","masivo","matar","materia","matiz","matriz","máximo","mayor","mazorca","mecha","medalla","medio","médula","mejilla","mejor","melena","melón","memoria","menor","mensaje","mente","menú","mercado","merengue","mérito","mes","mesón","meta","meter","método","metro","mezcla","miedo","miel","miembro","miga","mil","milagro","militar","millón","mimo","mina","minero","mínimo","minuto","miope","mirar","misa","miseria","misil","mismo","mitad","mito","mochila","moción","moda","modelo","moho","mojar","molde","moler","molino","momento","momia","monarca","moneda","monja","monto","moño","morada","morder","moreno","morir","morro","morsa","mortal","mosca","mostrar","motivo","mover","móvil","mozo","mucho","mudar","mueble","muela","muerte","muestra","mugre","mujer","mula","muleta","multa","mundo","muñeca","mural","muro","músculo","museo","musgo","música","muslo","nácar","nación","nadar","naipe","naranja","nariz","narrar","nasal","natal","nativo","natural","náusea","naval","nave","navidad","necio","néctar","negar","negocio","negro","neón","nervio","neto","neutro","nevar","nevera","nicho","nido","niebla","nieto","niñez","niño","nítido","nivel","nobleza","noche","nómina","noria","norma","norte","nota","noticia","novato","novela","novio","nube","nuca","núcleo","nudillo","nudo","nuera","nueve","nuez","nulo","número","nutria","oasis","obeso","obispo","objeto","obra","obrero","observar","obtener","obvio","oca","ocaso","océano","ochenta","ocho","ocio","ocre","octavo","octubre","oculto","ocupar","ocurrir","odiar","odio","odisea","oeste","ofensa","oferta","oficio","ofrecer","ogro","oído","oír","ojo","ola","oleada","olfato","olivo","olla","olmo","olor","olvido","ombligo","onda","onza","opaco","opción","ópera","opinar","oponer","optar","óptica","opuesto","oración","orador","oral","órbita","orca","orden","oreja","órgano","orgía","orgullo","oriente","origen","orilla","oro","orquesta","oruga","osadía","oscuro","osezno","oso","ostra","otoño","otro","oveja","óvulo","óxido","oxígeno","oyente","ozono","pacto","padre","paella","página","pago","país","pájaro","palabra","palco","paleta","pálido","palma","paloma","palpar","pan","panal","pánico","pantera","pañuelo","papá","papel","papilla","paquete","parar","parcela","pared","parir","paro","párpado","parque","párrafo","parte","pasar","paseo","pasión","paso","pasta","pata","patio","patria","pausa","pauta","pavo","payaso","peatón","pecado","pecera","pecho","pedal","pedir","pegar","peine","pelar","peldaño","pelea","peligro","pellejo","pelo","peluca","pena","pensar","peñón","peón","peor","pepino","pequeño","pera","percha","perder","pereza","perfil","perico","perla","permiso","perro","persona","pesa","pesca","pésimo","pestaña","pétalo","petróleo","pez","pezuña","picar","pichón","pie","piedra","pierna","pieza","pijama","pilar","piloto","pimienta","pino","pintor","pinza","piña","piojo","pipa","pirata","pisar","piscina","piso","pista","pitón","pizca","placa","plan","plata","playa","plaza","pleito","pleno","plomo","pluma","plural","pobre","poco","poder","podio","poema","poesía","poeta","polen","policía","pollo","polvo","pomada","pomelo","pomo","pompa","poner","porción","portal","posada","poseer","posible","poste","potencia","potro","pozo","prado","precoz","pregunta","premio","prensa","preso","previo","primo","príncipe","prisión","privar","proa","probar","proceso","producto","proeza","profesor","programa","prole","promesa","pronto","propio","próximo","prueba","público","puchero","pudor","pueblo","puerta","puesto","pulga","pulir","pulmón","pulpo","pulso","puma","punto","puñal","puño","pupa","pupila","puré","quedar","queja","quemar","querer","queso","quieto","química","quince","quitar","rábano","rabia","rabo","ración","radical","raíz","rama","rampa","rancho","rango","rapaz","rápido","rapto","rasgo","raspa","rato","rayo","raza","razón","reacción","realidad","rebaño","rebote","recaer","receta","rechazo","recoger","recreo","recto","recurso","red","redondo","reducir","reflejo","reforma","refrán","refugio","regalo","regir","regla","regreso","rehén","reino","reír","reja","relato","relevo","relieve","relleno","reloj","remar","remedio","remo","rencor","rendir","renta","reparto","repetir","reposo","reptil","res","rescate","resina","respeto","resto","resumen","retiro","retorno","retrato","reunir","revés","revista","rey","rezar","rico","riego","rienda","riesgo","rifa","rígido","rigor","rincón","riñón","río","riqueza","risa","ritmo","rito","rizo","roble","roce","rociar","rodar","rodeo","rodilla","roer","rojizo","rojo","romero","romper","ron","ronco","ronda","ropa","ropero","rosa","rosca","rostro","rotar","rubí","rubor","rudo","rueda","rugir","ruido","ruina","ruleta","rulo","rumbo","rumor","ruptura","ruta","rutina","sábado","saber","sabio","sable","sacar","sagaz","sagrado","sala","saldo","salero","salir","salmón","salón","salsa","salto","salud","salvar","samba","sanción","sandía","sanear","sangre","sanidad","sano","santo","sapo","saque","sardina","sartén","sastre","satán","sauna","saxofón","sección","seco","secreto","secta","sed","seguir","seis","sello","selva","semana","semilla","senda","sensor","señal","señor","separar","sepia","sequía","ser","serie","sermón","servir","sesenta","sesión","seta","setenta","severo","sexo","sexto","sidra","siesta","siete","siglo","signo","sílaba","silbar","silencio","silla","símbolo","simio","sirena","sistema","sitio","situar","sobre","socio","sodio","sol","solapa","soldado","soledad","sólido","soltar","solución","sombra","sondeo","sonido","sonoro","sonrisa","sopa","soplar","soporte","sordo","sorpresa","sorteo","sostén","sótano","suave","subir","suceso","sudor","suegra","suelo","sueño","suerte","sufrir","sujeto","sultán","sumar","superar","suplir","suponer","supremo","sur","surco","sureño","surgir","susto","sutil","tabaco","tabique","tabla","tabú","taco","tacto","tajo","talar","talco","talento","talla","talón","tamaño","tambor","tango","tanque","tapa","tapete","tapia","tapón","taquilla","tarde","tarea","tarifa","tarjeta","tarot","tarro","tarta","tatuaje","tauro","taza","tazón","teatro","techo","tecla","técnica","tejado","tejer","tejido","tela","teléfono","tema","temor","templo","tenaz","tender","tener","tenis","tenso","teoría","terapia","terco","término","ternura","terror","tesis","tesoro","testigo","tetera","texto","tez","tibio","tiburón","tiempo","tienda","tierra","tieso","tigre","tijera","tilde","timbre","tímido","timo","tinta","tío","típico","tipo","tira","tirón","titán","títere","título","tiza","toalla","tobillo","tocar","tocino","todo","toga","toldo","tomar","tono","tonto","topar","tope","toque","tórax","torero","tormenta","torneo","toro","torpedo","torre","torso","tortuga","tos","tosco","toser","tóxico","trabajo","tractor","traer","tráfico","trago","traje","tramo","trance","trato","trauma","trazar","trébol","tregua","treinta","tren","trepar","tres","tribu","trigo","tripa","triste","triunfo","trofeo","trompa","tronco","tropa","trote","trozo","truco","trueno","trufa","tubería","tubo","tuerto","tumba","tumor","túnel","túnica","turbina","turismo","turno","tutor","ubicar","úlcera","umbral","unidad","unir","universo","uno","untar","uña","urbano","urbe","urgente","urna","usar","usuario","útil","utopía","uva","vaca","vacío","vacuna","vagar","vago","vaina","vajilla","vale","válido","valle","valor","válvula","vampiro","vara","variar","varón","vaso","vecino","vector","vehículo","veinte","vejez","vela","velero","veloz","vena","vencer","venda","veneno","vengar","venir","venta","venus","ver","verano","verbo","verde","vereda","verja","verso","verter","vía","viaje","vibrar","vicio","víctima","vida","vídeo","vidrio","viejo","viernes","vigor","vil","villa","vinagre","vino","viñedo","violín","viral","virgo","virtud","visor","víspera","vista","vitamina","viudo","vivaz","vivero","vivir","vivo","volcán","volumen","volver","voraz","votar","voto","voz","vuelo","vulgar","yacer","yate","yegua","yema","yerno","yeso","yodo","yoga","yogur","zafiro","zanja","zapato","zarza","zona","zorro","zumo","zurdo"];t.exports=i},{}],9:[function(e,t,r){function i(e,t,r){if(!(this instanceof i))return new i(e,t,r);var n,a=typeof e;if("number"===a)n=e>0?e>>>0:0;else if("string"===a)"base64"===t&&(e=k(e)),n=i.byteLength(e,t);else{if("object"!==a||null===e)throw new TypeError("must start with number, buffer, array or string");"Buffer"===e.type&&C(e.data)&&(e=e.data),n=+e.length>0?Math.floor(+e.length):0}if(this.length>q)throw new RangeError("Attempt to allocate Buffer larger than maximum size: 0x"+q.toString(16)+" bytes");var o;i.TYPED_ARRAY_SUPPORT?o=i._augment(new Uint8Array(n)):(o=this,o.length=n,o._isBuffer=!0);var s;if(i.TYPED_ARRAY_SUPPORT&&"number"==typeof e.byteLength)o._set(e);else if(x(e))if(i.isBuffer(e))for(s=0;n>s;s++)o[s]=e.readUInt8(s);else for(s=0;n>s;s++)o[s]=(e[s]%256+256)%256;else if("string"===a)o.write(e,0,t);else if("number"===a&&!i.TYPED_ARRAY_SUPPORT&&!r)for(s=0;n>s;s++)o[s]=0;return o}function n(e,t,r,i){r=Number(r)||0;var n=e.length-r;i?(i=Number(i),i>n&&(i=n)):i=n;var a=t.length;if(a%2!==0)throw new Error("Invalid hex string");i>a/2&&(i=a/2);for(var o=0;i>o;o++){var s=parseInt(t.substr(2*o,2),16);if(isNaN(s))throw new Error("Invalid hex string");e[r+o]=s}return o}function a(e,t,r,i){var n=M(A(t),e,r,i);return n}function o(e,t,r,i){var n=M(I(t),e,r,i);return n}function s(e,t,r,i){return o(e,t,r,i)}function c(e,t,r,i){var n=M(z(t),e,r,i);return n}function f(e,t,r,i){var n=M(B(t),e,r,i,2);return n}function d(e,t,r){return P.fromByteArray(0===t&&r===e.length?e:e.slice(t,r))}function u(e,t,r){var i="",n="";r=Math.min(e.length,r);for(var a=t;r>a;a++)e[a]<=127?(i+=R(n)+String.fromCharCode(e[a]),n=""):n+="%"+e[a].toString(16);return i+R(n)}function h(e,t,r){var i="";r=Math.min(e.length,r);for(var n=t;r>n;n++)i+=String.fromCharCode(e[n]);return i}function l(e,t,r){return h(e,t,r)}function b(e,t,r){var i=e.length;(!t||0>t)&&(t=0),(!r||0>r||r>i)&&(r=i);for(var n="",a=t;r>a;a++)n+=j(e[a]);return n}function p(e,t,r){for(var i=e.slice(t,r),n="",a=0;a<i.length;a+=2)n+=String.fromCharCode(i[a]+256*i[a+1]);return n}function m(e,t,r){if(e%1!==0||0>e)throw new RangeError("offset is not uint");if(e+t>r)throw new RangeError("Trying to access beyond buffer length")}function g(e,t,r,n,a,o){if(!i.isBuffer(e))throw new TypeError("buffer must be a Buffer instance");if(t>a||o>t)throw new TypeError("value is out of bounds");if(r+n>e.length)throw new TypeError("index out of range")}function v(e,t,r,i){0>t&&(t=65535+t+1);for(var n=0,a=Math.min(e.length-r,2);a>n;n++)e[r+n]=(t&255<<8*(i?n:1-n))>>>8*(i?n:1-n)}function y(e,t,r,i){0>t&&(t=4294967295+t+1);for(var n=0,a=Math.min(e.length-r,4);a>n;n++)e[r+n]=t>>>8*(i?n:3-n)&255}function w(e,t,r,i,n,a){if(t>n||a>t)throw new TypeError("value is out of bounds");if(r+i>e.length)throw new TypeError("index out of range")}function _(e,t,r,i,n){return n||w(e,t,r,4,3.4028234663852886e38,-3.4028234663852886e38),T.write(e,t,r,i,23,4),r+4}function S(e,t,r,i,n){return n||w(e,t,r,8,1.7976931348623157e308,-1.7976931348623157e308),T.write(e,t,r,i,52,8),r+8}function k(e){for(e=E(e).replace(D,"");e.length%4!==0;)e+="=";return e}function E(e){return e.trim?e.trim():e.replace(/^\s+|\s+$/g,"")}function x(e){return C(e)||i.isBuffer(e)||e&&"object"==typeof e&&"number"==typeof e.length}function j(e){return 16>e?"0"+e.toString(16):e.toString(16)}function A(e){for(var t=[],r=0;r<e.length;r++){var i=e.charCodeAt(r);if(127>=i)t.push(i);else{var n=r;i>=55296&&57343>=i&&r++;for(var a=encodeURIComponent(e.slice(n,r+1)).substr(1).split("%"),o=0;o<a.length;o++)t.push(parseInt(a[o],16))}}return t}function I(e){for(var t=[],r=0;r<e.length;r++)t.push(255&e.charCodeAt(r));return t}function B(e){for(var t,r,i,n=[],a=0;a<e.length;a++)t=e.charCodeAt(a),r=t>>8,i=t%256,n.push(i),n.push(r);return n}function z(e){return P.toByteArray(e)}function M(e,t,r,i,n){n&&(i-=i%n);for(var a=0;i>a&&!(a+r>=t.length||a>=e.length);a++)t[a+r]=e[a];return a}function R(e){try{return decodeURIComponent(e)}catch(t){return String.fromCharCode(65533)}}var P=e("base64-js"),T=e("ieee754"),C=e("is-array");r.Buffer=i,r.SlowBuffer=i,r.INSPECT_MAX_BYTES=50,i.poolSize=8192;var q=1073741823;i.TYPED_ARRAY_SUPPORT=function(){try{var e=new ArrayBuffer(0),t=new Uint8Array(e);return t.foo=function(){return 42},42===t.foo()&&"function"==typeof t.subarray&&0===new Uint8Array(1).subarray(1,1).byteLength}catch(r){return!1}}(),i.isBuffer=function(e){return!(null==e||!e._isBuffer)},i.compare=function(e,t){if(!i.isBuffer(e)||!i.isBuffer(t))throw new TypeError("Arguments must be Buffers");for(var r=e.length,n=t.length,a=0,o=Math.min(r,n);o>a&&e[a]===t[a];a++);return a!==o&&(r=e[a],n=t[a]),n>r?-1:r>n?1:0},i.isEncoding=function(e){switch(String(e).toLowerCase()){case"hex":case"utf8":case"utf-8":case"ascii":case"binary":case"base64":case"raw":case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return!0;default:return!1}},i.concat=function(e,t){if(!C(e))throw new TypeError("Usage: Buffer.concat(list[, length])");if(0===e.length)return new i(0);if(1===e.length)return e[0];var r;if(void 0===t)for(t=0,r=0;r<e.length;r++)t+=e[r].length;var n=new i(t),a=0;for(r=0;r<e.length;r++){var o=e[r];o.copy(n,a),a+=o.length}return n},i.byteLength=function(e,t){var r;switch(e+="",t||"utf8"){case"ascii":case"binary":case"raw":r=e.length;break;case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":r=2*e.length;break;case"hex":r=e.length>>>1;break;case"utf8":case"utf-8":r=A(e).length;break;case"base64":r=z(e).length;break;default:r=e.length}return r},i.prototype.length=void 0,i.prototype.parent=void 0,i.prototype.toString=function(e,t,r){var i=!1;if(t>>>=0,r=void 0===r||r===1/0?this.length:r>>>0,e||(e="utf8"),0>t&&(t=0),r>this.length&&(r=this.length),t>=r)return"";for(;;)switch(e){case"hex":return b(this,t,r);case"utf8":case"utf-8":return u(this,t,r);case"ascii":return h(this,t,r);case"binary":return l(this,t,r);case"base64":return d(this,t,r);case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return p(this,t,r);default:if(i)throw new TypeError("Unknown encoding: "+e);e=(e+"").toLowerCase(),i=!0}},i.prototype.equals=function(e){if(!i.isBuffer(e))throw new TypeError("Argument must be a Buffer");return 0===i.compare(this,e)},i.prototype.inspect=function(){var e="",t=r.INSPECT_MAX_BYTES;return this.length>0&&(e=this.toString("hex",0,t).match(/.{2}/g).join(" "),this.length>t&&(e+=" ... ")),"<Buffer "+e+">"},i.prototype.compare=function(e){if(!i.isBuffer(e))throw new TypeError("Argument must be a Buffer");return i.compare(this,e)},i.prototype.get=function(e){return console.log(".get() is deprecated. Access using array indexes instead."),this.readUInt8(e)},i.prototype.set=function(e,t){return console.log(".set() is deprecated. Access using array indexes instead."),this.writeUInt8(e,t)},i.prototype.write=function(e,t,r,i){if(isFinite(t))isFinite(r)||(i=r,r=void 0);else{var d=i;i=t,t=r,r=d}t=Number(t)||0;var u=this.length-t;r?(r=Number(r),r>u&&(r=u)):r=u,i=String(i||"utf8").toLowerCase();var h;switch(i){case"hex":h=n(this,e,t,r);break;case"utf8":case"utf-8":h=a(this,e,t,r);break;case"ascii":h=o(this,e,t,r);break;case"binary":h=s(this,e,t,r);break;case"base64":h=c(this,e,t,r);break;case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":h=f(this,e,t,r);break;default:throw new TypeError("Unknown encoding: "+i)}return h},i.prototype.toJSON=function(){return{type:"Buffer",data:Array.prototype.slice.call(this._arr||this,0)}},i.prototype.slice=function(e,t){var r=this.length;if(e=~~e,t=void 0===t?r:~~t,0>e?(e+=r,0>e&&(e=0)):e>r&&(e=r),0>t?(t+=r,0>t&&(t=0)):t>r&&(t=r),e>t&&(t=e),i.TYPED_ARRAY_SUPPORT)return i._augment(this.subarray(e,t));for(var n=t-e,a=new i(n,void 0,!0),o=0;n>o;o++)a[o]=this[o+e];return a},i.prototype.readUInt8=function(e,t){return t||m(e,1,this.length),this[e]},i.prototype.readUInt16LE=function(e,t){return t||m(e,2,this.length),this[e]|this[e+1]<<8},i.prototype.readUInt16BE=function(e,t){return t||m(e,2,this.length),this[e]<<8|this[e+1]},i.prototype.readUInt32LE=function(e,t){return t||m(e,4,this.length),(this[e]|this[e+1]<<8|this[e+2]<<16)+16777216*this[e+3]},i.prototype.readUInt32BE=function(e,t){return t||m(e,4,this.length),16777216*this[e]+(this[e+1]<<16|this[e+2]<<8|this[e+3])},i.prototype.readInt8=function(e,t){return t||m(e,1,this.length),128&this[e]?-1*(255-this[e]+1):this[e]},i.prototype.readInt16LE=function(e,t){t||m(e,2,this.length);var r=this[e]|this[e+1]<<8;return 32768&r?4294901760|r:r},i.prototype.readInt16BE=function(e,t){t||m(e,2,this.length);var r=this[e+1]|this[e]<<8;return 32768&r?4294901760|r:r},i.prototype.readInt32LE=function(e,t){return t||m(e,4,this.length),this[e]|this[e+1]<<8|this[e+2]<<16|this[e+3]<<24},i.prototype.readInt32BE=function(e,t){return t||m(e,4,this.length),this[e]<<24|this[e+1]<<16|this[e+2]<<8|this[e+3]},i.prototype.readFloatLE=function(e,t){return t||m(e,4,this.length),T.read(this,e,!0,23,4)},i.prototype.readFloatBE=function(e,t){return t||m(e,4,this.length),T.read(this,e,!1,23,4)},i.prototype.readDoubleLE=function(e,t){return t||m(e,8,this.length),T.read(this,e,!0,52,8)},i.prototype.readDoubleBE=function(e,t){return t||m(e,8,this.length),T.read(this,e,!1,52,8)},i.prototype.writeUInt8=function(e,t,r){return e=+e,t>>>=0,r||g(this,e,t,1,255,0),i.TYPED_ARRAY_SUPPORT||(e=Math.floor(e)),this[t]=e,t+1},i.prototype.writeUInt16LE=function(e,t,r){return e=+e,t>>>=0,r||g(this,e,t,2,65535,0),i.TYPED_ARRAY_SUPPORT?(this[t]=e,this[t+1]=e>>>8):v(this,e,t,!0),t+2},i.prototype.writeUInt16BE=function(e,t,r){return e=+e,t>>>=0,r||g(this,e,t,2,65535,0),i.TYPED_ARRAY_SUPPORT?(this[t]=e>>>8,this[t+1]=e):v(this,e,t,!1),t+2},i.prototype.writeUInt32LE=function(e,t,r){return e=+e,t>>>=0,r||g(this,e,t,4,4294967295,0),i.TYPED_ARRAY_SUPPORT?(this[t+3]=e>>>24,this[t+2]=e>>>16,this[t+1]=e>>>8,this[t]=e):y(this,e,t,!0),t+4},i.prototype.writeUInt32BE=function(e,t,r){return e=+e,t>>>=0,r||g(this,e,t,4,4294967295,0),i.TYPED_ARRAY_SUPPORT?(this[t]=e>>>24,this[t+1]=e>>>16,this[t+2]=e>>>8,this[t+3]=e):y(this,e,t,!1),t+4},i.prototype.writeInt8=function(e,t,r){return e=+e,t>>>=0,r||g(this,e,t,1,127,-128),i.TYPED_ARRAY_SUPPORT||(e=Math.floor(e)),0>e&&(e=255+e+1),this[t]=e,t+1},i.prototype.writeInt16LE=function(e,t,r){return e=+e,t>>>=0,r||g(this,e,t,2,32767,-32768),i.TYPED_ARRAY_SUPPORT?(this[t]=e,this[t+1]=e>>>8):v(this,e,t,!0),t+2},i.prototype.writeInt16BE=function(e,t,r){return e=+e,t>>>=0,r||g(this,e,t,2,32767,-32768),i.TYPED_ARRAY_SUPPORT?(this[t]=e>>>8,this[t+1]=e):v(this,e,t,!1),t+2},i.prototype.writeInt32LE=function(e,t,r){return e=+e,t>>>=0,r||g(this,e,t,4,2147483647,-2147483648),i.TYPED_ARRAY_SUPPORT?(this[t]=e,this[t+1]=e>>>8,this[t+2]=e>>>16,this[t+3]=e>>>24):y(this,e,t,!0),t+4},i.prototype.writeInt32BE=function(e,t,r){return e=+e,t>>>=0,r||g(this,e,t,4,2147483647,-2147483648),0>e&&(e=4294967295+e+1),i.TYPED_ARRAY_SUPPORT?(this[t]=e>>>24,this[t+1]=e>>>16,this[t+2]=e>>>8,this[t+3]=e):y(this,e,t,!1),t+4},i.prototype.writeFloatLE=function(e,t,r){return _(this,e,t,!0,r)},i.prototype.writeFloatBE=function(e,t,r){return _(this,e,t,!1,r)},i.prototype.writeDoubleLE=function(e,t,r){return S(this,e,t,!0,r)},i.prototype.writeDoubleBE=function(e,t,r){return S(this,e,t,!1,r)},i.prototype.copy=function(e,t,r,n){var a=this;if(r||(r=0),n||0===n||(n=this.length),t||(t=0),n!==r&&0!==e.length&&0!==a.length){if(r>n)throw new TypeError("sourceEnd < sourceStart");if(0>t||t>=e.length)throw new TypeError("targetStart out of bounds");if(0>r||r>=a.length)throw new TypeError("sourceStart out of bounds");if(0>n||n>a.length)throw new TypeError("sourceEnd out of bounds");n>this.length&&(n=this.length),e.length-t<n-r&&(n=e.length-t+r);var o=n-r;if(1e3>o||!i.TYPED_ARRAY_SUPPORT)for(var s=0;o>s;s++)e[s+t]=this[s+r];else e._set(this.subarray(r,r+o),t)}},i.prototype.fill=function(e,t,r){if(e||(e=0),t||(t=0),r||(r=this.length),t>r)throw new TypeError("end < start");if(r!==t&&0!==this.length){if(0>t||t>=this.length)throw new TypeError("start out of bounds");if(0>r||r>this.length)throw new TypeError("end out of bounds");var i;if("number"==typeof e)for(i=t;r>i;i++)this[i]=e;else{var n=A(e.toString()),a=n.length;for(i=t;r>i;i++)this[i]=n[i%a]}return this}},i.prototype.toArrayBuffer=function(){if("undefined"!=typeof Uint8Array){if(i.TYPED_ARRAY_SUPPORT)return new i(this).buffer;for(var e=new Uint8Array(this.length),t=0,r=e.length;r>t;t+=1)e[t]=this[t];return e.buffer}throw new TypeError("Buffer.toArrayBuffer not supported in this browser")};var L=i.prototype;i._augment=function(e){return e.constructor=i,e._isBuffer=!0,e._get=e.get,e._set=e.set,e.get=L.get,e.set=L.set,e.write=L.write,e.toString=L.toString,e.toLocaleString=L.toString,e.toJSON=L.toJSON,e.equals=L.equals,e.compare=L.compare,e.copy=L.copy,e.slice=L.slice,e.readUInt8=L.readUInt8,e.readUInt16LE=L.readUInt16LE,e.readUInt16BE=L.readUInt16BE,e.readUInt32LE=L.readUInt32LE,e.readUInt32BE=L.readUInt32BE,e.readInt8=L.readInt8,e.readInt16LE=L.readInt16LE,e.readInt16BE=L.readInt16BE,e.readInt32LE=L.readInt32LE,e.readInt32BE=L.readInt32BE,e.readFloatLE=L.readFloatLE,e.readFloatBE=L.readFloatBE,e.readDoubleLE=L.readDoubleLE,e.readDoubleBE=L.readDoubleBE,e.writeUInt8=L.writeUInt8,e.writeUInt16LE=L.writeUInt16LE,e.writeUInt16BE=L.writeUInt16BE,e.writeUInt32LE=L.writeUInt32LE,e.writeUInt32BE=L.writeUInt32BE,e.writeInt8=L.writeInt8,e.writeInt16LE=L.writeInt16LE,e.writeInt16BE=L.writeInt16BE,e.writeInt32LE=L.writeInt32LE,e.writeInt32BE=L.writeInt32BE,e.writeFloatLE=L.writeFloatLE,e.writeFloatBE=L.writeFloatBE,e.writeDoubleLE=L.writeDoubleLE,e.writeDoubleBE=L.writeDoubleBE,e.fill=L.fill,e.inspect=L.inspect,e.toArrayBuffer=L.toArrayBuffer,e};var D=/[^+\/0-9A-z]/g},{"base64-js":10,ieee754:11,"is-array":12}],10:[function(e,t,r){var i="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";!function(e){"use strict";function t(e){var t=e.charCodeAt(0);return t===o?62:t===s?63:c>t?-1:c+10>t?t-c+26+26:d+26>t?t-d:f+26>t?t-f+26:void 0}function r(e){function r(e){f[u++]=e}var i,n,o,s,c,f;if(e.length%4>0)throw new Error("Invalid string. Length must be a multiple of 4");var d=e.length;c="="===e.charAt(d-2)?2:"="===e.charAt(d-1)?1:0,f=new a(3*e.length/4-c),o=c>0?e.length-4:e.length;var u=0;for(i=0,n=0;o>i;i+=4,n+=3)s=t(e.charAt(i))<<18|t(e.charAt(i+1))<<12|t(e.charAt(i+2))<<6|t(e.charAt(i+3)),r((16711680&s)>>16),r((65280&s)>>8),r(255&s);return 2===c?(s=t(e.charAt(i))<<2|t(e.charAt(i+1))>>4,r(255&s)):1===c&&(s=t(e.charAt(i))<<10|t(e.charAt(i+1))<<4|t(e.charAt(i+2))>>2,r(s>>8&255),r(255&s)),f}function n(e){function t(e){return i.charAt(e)}function r(e){return t(e>>18&63)+t(e>>12&63)+t(e>>6&63)+t(63&e)}var n,a,o,s=e.length%3,c="";

for(n=0,o=e.length-s;o>n;n+=3)a=(e[n]<<16)+(e[n+1]<<8)+e[n+2],c+=r(a);switch(s){case 1:a=e[e.length-1],c+=t(a>>2),c+=t(a<<4&63),c+="==";break;case 2:a=(e[e.length-2]<<8)+e[e.length-1],c+=t(a>>10),c+=t(a>>4&63),c+=t(a<<2&63),c+="="}return c}var a="undefined"!=typeof Uint8Array?Uint8Array:Array,o="+".charCodeAt(0),s="/".charCodeAt(0),c="0".charCodeAt(0),f="a".charCodeAt(0),d="A".charCodeAt(0);e.toByteArray=r,e.fromByteArray=n}("undefined"==typeof r?this.base64js={}:r)},{}],11:[function(e,t,r){r.read=function(e,t,r,i,n){var a,o,s=8*n-i-1,c=(1<<s)-1,f=c>>1,d=-7,u=r?n-1:0,h=r?-1:1,l=e[t+u];for(u+=h,a=l&(1<<-d)-1,l>>=-d,d+=s;d>0;a=256*a+e[t+u],u+=h,d-=8);for(o=a&(1<<-d)-1,a>>=-d,d+=i;d>0;o=256*o+e[t+u],u+=h,d-=8);if(0===a)a=1-f;else{if(a===c)return o?0/0:(l?-1:1)*(1/0);o+=Math.pow(2,i),a-=f}return(l?-1:1)*o*Math.pow(2,a-i)},r.write=function(e,t,r,i,n,a){var o,s,c,f=8*a-n-1,d=(1<<f)-1,u=d>>1,h=23===n?Math.pow(2,-24)-Math.pow(2,-77):0,l=i?0:a-1,b=i?1:-1,p=0>t||0===t&&0>1/t?1:0;for(t=Math.abs(t),isNaN(t)||t===1/0?(s=isNaN(t)?1:0,o=d):(o=Math.floor(Math.log(t)/Math.LN2),t*(c=Math.pow(2,-o))<1&&(o--,c*=2),t+=o+u>=1?h/c:h*Math.pow(2,1-u),t*c>=2&&(o++,c/=2),o+u>=d?(s=0,o=d):o+u>=1?(s=(t*c-1)*Math.pow(2,n),o+=u):(s=t*Math.pow(2,u-1)*Math.pow(2,n),o=0));n>=8;e[r+l]=255&s,l+=b,s/=256,n-=8);for(o=o<<n|s,f+=n;f>0;e[r+l]=255&o,l+=b,o/=256,f-=8);e[r+l-b]|=128*p}},{}],12:[function(e,t,r){var i=Array.isArray,n=Object.prototype.toString;t.exports=i||function(e){return!!e&&"[object Array]"==n.call(e)}},{}],13:[function(e,t,r){"use strict";r.randomBytes=r.rng=r.pseudoRandomBytes=r.prng=e("randombytes"),r.createHash=r.Hash=e("create-hash"),r.createHmac=r.Hmac=e("create-hmac");var i=["sha1","sha224","sha256","sha384","sha512","md5","rmd160"].concat(Object.keys(e("browserify-sign/algos")));r.getHashes=function(){return i};var n=e("pbkdf2");r.pbkdf2=n.pbkdf2,r.pbkdf2Sync=n.pbkdf2Sync;var a=e("browserify-aes");["Cipher","createCipher","Cipheriv","createCipheriv","Decipher","createDecipher","Decipheriv","createDecipheriv","getCiphers","listCiphers"].forEach(function(e){r[e]=a[e]});var o=e("diffie-hellman");["DiffieHellmanGroup","createDiffieHellmanGroup","getDiffieHellman","createDiffieHellman","DiffieHellman"].forEach(function(e){r[e]=o[e]});var s=e("browserify-sign");["createSign","Sign","createVerify","Verify"].forEach(function(e){r[e]=s[e]}),r.createECDH=e("create-ecdh");var c=e("public-encrypt");["publicEncrypt","privateEncrypt","publicDecrypt","privateDecrypt"].forEach(function(e){r[e]=c[e]}),["createCredentials"].forEach(function(e){r[e]=function(){throw new Error(["sorry, "+e+" is not implemented yet","we accept pull requests","https://github.com/crypto-browserify/crypto-browserify"].join("\n"))}})},{"browserify-aes":17,"browserify-sign":33,"browserify-sign/algos":32,"create-ecdh":79,"create-hash":101,"create-hmac":113,"diffie-hellman":114,pbkdf2:121,"public-encrypt":122,randombytes:149}],14:[function(e,t,r){(function(r){function i(e,t,i){r.isBuffer(e)||(e=new r(e,"binary")),t/=8,i=i||0;for(var a,o,s=0,c=0,f=new r(t),d=new r(i),u=0,h=[];;){if(u++>0&&h.push(a),h.push(e),a=n(r.concat(h)),h=[],o=0,t>0)for(;;){if(0===t)break;if(o===a.length)break;f[s++]=a[o],t--,o++}if(i>0&&o!==a.length)for(;;){if(0===i)break;if(o===a.length)break;d[c++]=a[o],i--,o++}if(0===t&&0===i)break}for(o=0;o<a.length;o++)a[o]=0;return{key:f,iv:d}}var n=e("create-hash/md5");t.exports=i}).call(this,e("buffer").Buffer)},{buffer:9,"create-hash/md5":103}],15:[function(e,t,r){(function(e){function t(e){var t,r;return t=e>s||0>e?(r=Math.abs(e)%s,0>e?s-r:r):e}function i(e){var t,r,i;for(t=r=0,i=e.length;i>=0?i>r:r>i;t=i>=0?++r:--r)e[t]=0;return!1}function n(){var e;this.SBOX=[],this.INV_SBOX=[],this.SUB_MIX=function(){var t,r;for(r=[],e=t=0;4>t;e=++t)r.push([]);return r}(),this.INV_SUB_MIX=function(){var t,r;for(r=[],e=t=0;4>t;e=++t)r.push([]);return r}(),this.init(),this.RCON=[0,1,2,4,8,16,32,64,128,27,54]}function a(e){for(var t=e.length/4,r=new Array(t),i=-1;++i<t;)r[i]=e.readUInt32BE(4*i);return r}function o(e){this._key=a(e),this._doReset()}var s=Math.pow(2,32);n.prototype.init=function(){var e,t,r,i,n,a,o,s,c,f;for(e=function(){var e,r;for(r=[],t=e=0;256>e;t=++e)r.push(128>t?t<<1:t<<1^283);return r}(),n=0,c=0,t=f=0;256>f;t=++f)r=c^c<<1^c<<2^c<<3^c<<4,r=r>>>8^255&r^99,this.SBOX[n]=r,this.INV_SBOX[r]=n,a=e[n],o=e[a],s=e[o],i=257*e[r]^16843008*r,this.SUB_MIX[0][n]=i<<24|i>>>8,this.SUB_MIX[1][n]=i<<16|i>>>16,this.SUB_MIX[2][n]=i<<8|i>>>24,this.SUB_MIX[3][n]=i,i=16843009*s^65537*o^257*a^16843008*n,this.INV_SUB_MIX[0][r]=i<<24|i>>>8,this.INV_SUB_MIX[1][r]=i<<16|i>>>16,this.INV_SUB_MIX[2][r]=i<<8|i>>>24,this.INV_SUB_MIX[3][r]=i,0===n?n=c=1:(n=a^e[e[e[s^a]]],c^=e[e[c]]);return!0};var c=new n;o.blockSize=16,o.prototype.blockSize=o.blockSize,o.keySize=32,o.prototype.keySize=o.keySize,o.prototype._doReset=function(){var e,t,r,i,n,a,o,s;for(r=this._key,t=r.length,this._nRounds=t+6,n=4*(this._nRounds+1),this._keySchedule=[],i=o=0;n>=0?n>o:o>n;i=n>=0?++o:--o)this._keySchedule[i]=t>i?r[i]:(a=this._keySchedule[i-1],i%t===0?(a=a<<8|a>>>24,a=c.SBOX[a>>>24]<<24|c.SBOX[a>>>16&255]<<16|c.SBOX[a>>>8&255]<<8|c.SBOX[255&a],a^=c.RCON[i/t|0]<<24):t>6&&i%t===4?a=c.SBOX[a>>>24]<<24|c.SBOX[a>>>16&255]<<16|c.SBOX[a>>>8&255]<<8|c.SBOX[255&a]:void 0,this._keySchedule[i-t]^a);for(this._invKeySchedule=[],e=s=0;n>=0?n>s:s>n;e=n>=0?++s:--s)i=n-e,a=this._keySchedule[i-(e%4?0:4)],this._invKeySchedule[e]=4>e||4>=i?a:c.INV_SUB_MIX[0][c.SBOX[a>>>24]]^c.INV_SUB_MIX[1][c.SBOX[a>>>16&255]]^c.INV_SUB_MIX[2][c.SBOX[a>>>8&255]]^c.INV_SUB_MIX[3][c.SBOX[255&a]];return!0},o.prototype.encryptBlock=function(t){t=a(new e(t));var r=this._doCryptBlock(t,this._keySchedule,c.SUB_MIX,c.SBOX),i=new e(16);return i.writeUInt32BE(r[0],0),i.writeUInt32BE(r[1],4),i.writeUInt32BE(r[2],8),i.writeUInt32BE(r[3],12),i},o.prototype.decryptBlock=function(t){t=a(new e(t));var r=[t[3],t[1]];t[1]=r[0],t[3]=r[1];var i=this._doCryptBlock(t,this._invKeySchedule,c.INV_SUB_MIX,c.INV_SBOX),n=new e(16);return n.writeUInt32BE(i[0],0),n.writeUInt32BE(i[3],4),n.writeUInt32BE(i[2],8),n.writeUInt32BE(i[1],12),n},o.prototype.scrub=function(){i(this._keySchedule),i(this._invKeySchedule),i(this._key)},o.prototype._doCryptBlock=function(e,r,i,n){var a,o,s,c,f,d,u,h,l,b,p,m;for(s=e[0]^r[0],c=e[1]^r[1],f=e[2]^r[2],d=e[3]^r[3],a=4,o=p=1,m=this._nRounds;m>=1?m>p:p>m;o=m>=1?++p:--p)u=i[0][s>>>24]^i[1][c>>>16&255]^i[2][f>>>8&255]^i[3][255&d]^r[a++],h=i[0][c>>>24]^i[1][f>>>16&255]^i[2][d>>>8&255]^i[3][255&s]^r[a++],l=i[0][f>>>24]^i[1][d>>>16&255]^i[2][s>>>8&255]^i[3][255&c]^r[a++],b=i[0][d>>>24]^i[1][s>>>16&255]^i[2][c>>>8&255]^i[3][255&f]^r[a++],s=u,c=h,f=l,d=b;return u=(n[s>>>24]<<24|n[c>>>16&255]<<16|n[f>>>8&255]<<8|n[255&d])^r[a++],h=(n[c>>>24]<<24|n[f>>>16&255]<<16|n[d>>>8&255]<<8|n[255&s])^r[a++],l=(n[f>>>24]<<24|n[d>>>16&255]<<16|n[s>>>8&255]<<8|n[255&c])^r[a++],b=(n[d>>>24]<<24|n[s>>>16&255]<<16|n[c>>>8&255]<<8|n[255&f])^r[a++],[t(u),t(h),t(l),t(b)]},r.AES=o}).call(this,e("buffer").Buffer)},{buffer:9}],16:[function(e,t,r){(function(r){function i(e,t,n,s){if(!(this instanceof i))return new i(e,t,n);o.call(this),this._finID=r.concat([n,new r([0,0,0,1])]),n=r.concat([n,new r([0,0,0,2])]),this._cipher=new a.AES(t),this._prev=new r(n.length),this._cache=new r(""),this._secCache=new r(""),this._decrypt=s,this._alen=0,this._len=0,n.copy(this._prev),this._mode=e;var f=new r(4);f.fill(0),this._ghash=new c(this._cipher.encryptBlock(f)),this._authTag=null,this._called=!1}function n(e,t){var r=0;e.length!==t.length&&r++;for(var i=Math.min(e.length,t.length),n=-1;++n<i;)r+=e[n]^t[n];return r}var a=e("./aes"),o=e("./cipherBase"),s=e("inherits"),c=e("./ghash"),f=e("./xor");s(i,o),t.exports=i,i.prototype._update=function(e){if(!this._called&&this._alen){var t=16-this._alen%16;16>t&&(t=new r(t),t.fill(0),this._ghash.update(t))}this._called=!0;var i=this._mode.encrypt(this,e);return this._ghash.update(this._decrypt?e:i),this._len+=e.length,i},i.prototype._final=function(){if(this._decrypt&&!this._authTag)throw new Error("Unsupported state or unable to authenticate data");var e=f(this._ghash["final"](8*this._alen,8*this._len),this._cipher.encryptBlock(this._finID));if(this._decrypt){if(n(e,this._authTag))throw new Error("Unsupported state or unable to authenticate data")}else this._authTag=e;this._cipher.scrub()},i.prototype.getAuthTag=function(){if(!this._decrypt&&r.isBuffer(this._authTag))return this._authTag;throw new Error("Attempting to get auth tag in unsupported state")},i.prototype.setAuthTag=function(e){if(!this._decrypt)throw new Error("Attempting to set auth tag in unsupported state");this._authTag=e},i.prototype.setAAD=function(e){if(this._called)throw new Error("Attempting to set AAD in unsupported state");this._ghash.update(e),this._alen+=e.length}}).call(this,e("buffer").Buffer)},{"./aes":15,"./cipherBase":18,"./ghash":21,"./xor":31,buffer:9,inherits:151}],17:[function(e,t,r){function i(){return Object.keys(o)}var n=e("./encrypter");r.createCipher=r.Cipher=n.createCipher,r.createCipheriv=r.Cipheriv=n.createCipheriv;var a=e("./decrypter");r.createDecipher=r.Decipher=a.createDecipher,r.createDecipheriv=r.Decipheriv=a.createDecipheriv;var o=e("./modes");r.listCiphers=r.getCiphers=i},{"./decrypter":19,"./encrypter":20,"./modes":22}],18:[function(e,t,r){(function(r){function i(){n.call(this)}var n=e("stream").Transform,a=e("inherits");t.exports=i,a(i,n),i.prototype.update=function(e,t,i){"string"==typeof e&&(e=new r(e,t));var n=this._update(e);return i&&(n=n.toString(i)),n},i.prototype._transform=function(e,t,r){this.push(this._update(e)),r()},i.prototype._flush=function(e){try{this.push(this._final())}catch(t){return e(t)}e()},i.prototype["final"]=function(e){var t=this._final()||new r("");return e&&(t=t.toString(e)),t}}).call(this,e("buffer").Buffer)},{buffer:9,inherits:151,stream:165}],19:[function(e,t,r){(function(t){function i(e,r,a){return this instanceof i?(f.call(this),this._cache=new n,this._last=void 0,this._cipher=new c.AES(r),this._prev=new t(a.length),a.copy(this._prev),this._mode=e,void(this._autopadding=!0)):new i(e,r,a)}function n(){return this instanceof n?void(this.cache=new t("")):new n}function a(e){for(var t=e[15],r=-1;++r<t;)if(e[r+(16-t)]!==t)throw new Error("unable to decrypt data");return 16!==t?e.slice(0,16-t):void 0}function o(e,r,n){var a=u[e.toLowerCase()];if(!a)throw new TypeError("invalid suite type");if("string"==typeof n&&(n=new t(n)),"string"==typeof r&&(r=new t(r)),r.length!==a.key/8)throw new TypeError("invalid key length "+r.length);if(n.length!==a.iv)throw new TypeError("invalid iv length "+n.length);return"stream"===a.type?new h(p[a.mode],r,n,!0):"auth"===a.type?new l(p[a.mode],r,n,!0):new i(p[a.mode],r,n)}function s(e,t){var r=u[e.toLowerCase()];if(!r)throw new TypeError("invalid suite type");var i=b(t,r.key,r.iv);return o(e,i.key,i.iv)}var c=e("./aes"),f=e("./cipherBase"),d=e("inherits"),u=e("./modes"),h=e("./streamCipher"),l=e("./authCipher"),b=e("./EVP_BytesToKey");d(i,f),i.prototype._update=function(e){this._cache.add(e);for(var r,i,n=[];r=this._cache.get(this._autopadding);)i=this._mode.decrypt(this,r),n.push(i);return t.concat(n)},i.prototype._final=function(){var e=this._cache.flush();if(this._autopadding)return a(this._mode.decrypt(this,e));if(e)throw new Error("data not multiple of block length")},i.prototype.setAutoPadding=function(e){this._autopadding=!!e},n.prototype.add=function(e){this.cache=t.concat([this.cache,e])},n.prototype.get=function(e){var t;if(e){if(this.cache.length>16)return t=this.cache.slice(0,16),this.cache=this.cache.slice(16),t}else if(this.cache.length>=16)return t=this.cache.slice(0,16),this.cache=this.cache.slice(16),t;return null},n.prototype.flush=function(){return this.cache.length?this.cache:void 0};var p={ECB:e("./modes/ecb"),CBC:e("./modes/cbc"),CFB:e("./modes/cfb"),CFB8:e("./modes/cfb8"),CFB1:e("./modes/cfb1"),OFB:e("./modes/ofb"),CTR:e("./modes/ctr"),GCM:e("./modes/ctr")};r.createDecipher=s,r.createDecipheriv=o}).call(this,e("buffer").Buffer)},{"./EVP_BytesToKey":14,"./aes":15,"./authCipher":16,"./cipherBase":18,"./modes":22,"./modes/cbc":23,"./modes/cfb":24,"./modes/cfb1":25,"./modes/cfb8":26,"./modes/ctr":27,"./modes/ecb":28,"./modes/ofb":29,"./streamCipher":30,buffer:9,inherits:151}],20:[function(e,t,r){(function(t){function i(e,r,a){return this instanceof i?(c.call(this),this._cache=new n,this._cipher=new s.AES(r),this._prev=new t(a.length),a.copy(this._prev),this._mode=e,void(this._autopadding=!0)):new i(e,r,a)}function n(){return this instanceof n?void(this.cache=new t("")):new n}function a(e,r,n){var a=d[e.toLowerCase()];if(!a)throw new TypeError("invalid suite type");if("string"==typeof n&&(n=new t(n)),"string"==typeof r&&(r=new t(r)),r.length!==a.key/8)throw new TypeError("invalid key length "+r.length);if(n.length!==a.iv)throw new TypeError("invalid iv length "+n.length);return"stream"===a.type?new h(b[a.mode],r,n):"auth"===a.type?new l(b[a.mode],r,n):new i(b[a.mode],r,n)}function o(e,t){var r=d[e.toLowerCase()];if(!r)throw new TypeError("invalid suite type");var i=u(t,r.key,r.iv);return a(e,i.key,i.iv)}var s=e("./aes"),c=e("./cipherBase"),f=e("inherits"),d=e("./modes"),u=e("./EVP_BytesToKey"),h=e("./streamCipher"),l=e("./authCipher");f(i,c),i.prototype._update=function(e){this._cache.add(e);for(var r,i,n=[];r=this._cache.get();)i=this._mode.encrypt(this,r),n.push(i);return t.concat(n)},i.prototype._final=function(){var e=this._cache.flush();if(this._autopadding)return e=this._mode.encrypt(this,e),this._cipher.scrub(),e;if("10101010101010101010101010101010"!==e.toString("hex"))throw this._cipher.scrub(),new Error("data not multiple of block length")},i.prototype.setAutoPadding=function(e){this._autopadding=!!e},n.prototype.add=function(e){this.cache=t.concat([this.cache,e])},n.prototype.get=function(){if(this.cache.length>15){var e=this.cache.slice(0,16);return this.cache=this.cache.slice(16),e}return null},n.prototype.flush=function(){for(var e=16-this.cache.length,r=new t(e),i=-1;++i<e;)r.writeUInt8(e,i);var n=t.concat([this.cache,r]);return n};var b={ECB:e("./modes/ecb"),CBC:e("./modes/cbc"),CFB:e("./modes/cfb"),CFB8:e("./modes/cfb8"),CFB1:e("./modes/cfb1"),OFB:e("./modes/ofb"),CTR:e("./modes/ctr"),GCM:e("./modes/ctr")};r.createCipheriv=a,r.createCipher=o}).call(this,e("buffer").Buffer)},{"./EVP_BytesToKey":14,"./aes":15,"./authCipher":16,"./cipherBase":18,"./modes":22,"./modes/cbc":23,"./modes/cfb":24,"./modes/cfb1":25,"./modes/cfb8":26,"./modes/ctr":27,"./modes/ecb":28,"./modes/ofb":29,"./streamCipher":30,buffer:9,inherits:151}],21:[function(e,t,r){(function(e){function r(t){this.h=t,this.state=new e(16),this.state.fill(0),this.cache=new e("")}function i(e){return[e.readUInt32BE(0),e.readUInt32BE(4),e.readUInt32BE(8),e.readUInt32BE(12)]}function n(t){t=t.map(a);var r=new e(16);return r.writeUInt32BE(t[0],0),r.writeUInt32BE(t[1],4),r.writeUInt32BE(t[2],8),r.writeUInt32BE(t[3],12),r}function a(e){var t,r;return t=e>c||0>e?(r=Math.abs(e)%c,0>e?c-r:r):e}function o(e,t){return[e[0]^t[0],e[1]^t[1],e[2]^t[2],e[3]^t[3]]}var s=new e(16);s.fill(0),t.exports=r,r.prototype.ghash=function(e){for(var t=-1;++t<e.length;)this.state[t]^=e[t];this._multiply()},r.prototype._multiply=function(){for(var e,t,r,a=i(this.h),s=[0,0,0,0],c=-1;++c<128;){for(t=0!==(this.state[~~(c/8)]&1<<7-c%8),t&&(s=o(s,a)),r=0!==(1&a[3]),e=3;e>0;e--)a[e]=a[e]>>>1|(1&a[e-1])<<31;a[0]=a[0]>>>1,r&&(a[0]=a[0]^225<<24)}this.state=n(s)},r.prototype.update=function(t){this.cache=e.concat([this.cache,t]);for(var r;this.cache.length>=16;)r=this.cache.slice(0,16),this.cache=this.cache.slice(16),this.ghash(r)},r.prototype["final"]=function(t,r){return this.cache.length&&this.ghash(e.concat([this.cache,s],16)),this.ghash(n([0,t,0,r])),this.state};var c=Math.pow(2,32)}).call(this,e("buffer").Buffer)},{buffer:9}],22:[function(e,t,r){r["aes-128-ecb"]={cipher:"AES",key:128,iv:0,mode:"ECB",type:"block"},r["aes-192-ecb"]={cipher:"AES",key:192,iv:0,mode:"ECB",type:"block"},r["aes-256-ecb"]={cipher:"AES",key:256,iv:0,mode:"ECB",type:"block"},r["aes-128-cbc"]={cipher:"AES",key:128,iv:16,mode:"CBC",type:"block"},r["aes-192-cbc"]={cipher:"AES",key:192,iv:16,mode:"CBC",type:"block"},r["aes-256-cbc"]={cipher:"AES",key:256,iv:16,mode:"CBC",type:"block"},r.aes128=r["aes-128-cbc"],r.aes192=r["aes-192-cbc"],r.aes256=r["aes-256-cbc"],r["aes-128-cfb"]={cipher:"AES",key:128,iv:16,mode:"CFB",type:"stream"},r["aes-192-cfb"]={cipher:"AES",key:192,iv:16,mode:"CFB",type:"stream"},r["aes-256-cfb"]={cipher:"AES",key:256,iv:16,mode:"CFB",type:"stream"},r["aes-128-cfb8"]={cipher:"AES",key:128,iv:16,mode:"CFB8",type:"stream"},r["aes-192-cfb8"]={cipher:"AES",key:192,iv:16,mode:"CFB8",type:"stream"},r["aes-256-cfb8"]={cipher:"AES",key:256,iv:16,mode:"CFB8",type:"stream"},r["aes-128-cfb1"]={cipher:"AES",key:128,iv:16,mode:"CFB1",type:"stream"},r["aes-192-cfb1"]={cipher:"AES",key:192,iv:16,mode:"CFB1",type:"stream"},r["aes-256-cfb1"]={cipher:"AES",key:256,iv:16,mode:"CFB1",type:"stream"},r["aes-128-ofb"]={cipher:"AES",key:128,iv:16,mode:"OFB",type:"stream"},r["aes-192-ofb"]={cipher:"AES",key:192,iv:16,mode:"OFB",type:"stream"},r["aes-256-ofb"]={cipher:"AES",key:256,iv:16,mode:"OFB",type:"stream"},r["aes-128-ctr"]={cipher:"AES",key:128,iv:16,mode:"CTR",type:"stream"},r["aes-192-ctr"]={cipher:"AES",key:192,iv:16,mode:"CTR",type:"stream"},r["aes-256-ctr"]={cipher:"AES",key:256,iv:16,mode:"CTR",type:"stream"},r["aes-128-gcm"]={cipher:"AES",key:128,iv:12,mode:"GCM",type:"auth"},r["aes-192-gcm"]={cipher:"AES",key:192,iv:12,mode:"GCM",type:"auth"},r["aes-256-gcm"]={cipher:"AES",key:256,iv:12,mode:"GCM",type:"auth"}},{}],23:[function(e,t,r){var i=e("../xor");r.encrypt=function(e,t){var r=i(t,e._prev);return e._prev=e._cipher.encryptBlock(r),e._prev},r.decrypt=function(e,t){var r=e._prev;e._prev=t;var n=e._cipher.decryptBlock(t);return i(n,r)}},{"../xor":31}],24:[function(e,t,r){(function(t){function i(e,r,i){var a=r.length,o=n(r,e._cache);return e._cache=e._cache.slice(a),e._prev=t.concat([e._prev,i?r:o]),o}var n=e("../xor");r.encrypt=function(e,r,n){for(var a,o=new t("");r.length;){if(0===e._cache.length&&(e._cache=e._cipher.encryptBlock(e._prev),e._prev=new t("")),!(e._cache.length<=r.length)){o=t.concat([o,i(e,r,n)]);break}a=e._cache.length,o=t.concat([o,i(e,r.slice(0,a),n)]),r=r.slice(a)}return o}}).call(this,e("buffer").Buffer)},{"../xor":31,buffer:9}],25:[function(e,t,r){(function(e){function t(e,t,r){for(var n,a,o,s=-1,c=8,f=0;++s<c;)n=e._cipher.encryptBlock(e._prev),a=t&1<<7-s?128:0,o=n[0]^a,f+=(128&o)>>s%8,e._prev=i(e._prev,r?a:o);return f}function i(t,r){var i=t.length,n=-1,a=new e(t.length);for(t=e.concat([t,new e([r])]);++n<i;)a[n]=t[n]<<1|t[n+1]>>7;return a}r.encrypt=function(r,i,n){for(var a=i.length,o=new e(a),s=-1;++s<a;)o[s]=t(r,i[s],n);return o}}).call(this,e("buffer").Buffer)},{buffer:9}],26:[function(e,t,r){(function(e){function t(t,r,i){var n=t._cipher.encryptBlock(t._prev),a=n[0]^r;return t._prev=e.concat([t._prev.slice(1),new e([i?r:a])]),a}r.encrypt=function(r,i,n){for(var a=i.length,o=new e(a),s=-1;++s<a;)o[s]=t(r,i[s],n);return o}}).call(this,e("buffer").Buffer)},{buffer:9}],27:[function(e,t,r){(function(t){function i(e){var t=e._cipher.encryptBlock(e._prev);return n(e._prev),t}function n(e){for(var t,r=e.length;r--;){if(t=e.readUInt8(r),255!==t){t++,e.writeUInt8(t,r);break}e.writeUInt8(0,r)}}var a=e("../xor");r.encrypt=function(e,r){for(;e._cache.length<r.length;)e._cache=t.concat([e._cache,i(e)]);var n=e._cache.slice(0,r.length);return e._cache=e._cache.slice(r.length),a(r,n)}}).call(this,e("buffer").Buffer)},{"../xor":31,buffer:9}],28:[function(e,t,r){r.encrypt=function(e,t){return e._cipher.encryptBlock(t)},r.decrypt=function(e,t){return e._cipher.decryptBlock(t)}},{}],29:[function(e,t,r){(function(t){function i(e){return e._prev=e._cipher.encryptBlock(e._prev),e._prev}var n=e("../xor");r.encrypt=function(e,r){for(;e._cache.length<r.length;)e._cache=t.concat([e._cache,i(e)]);var a=e._cache.slice(0,r.length);return e._cache=e._cache.slice(r.length),n(r,a)}}).call(this,e("buffer").Buffer)},{"../xor":31,buffer:9}],30:[function(e,t,r){(function(r){function i(e,t,o,s){return this instanceof i?(a.call(this),this._cipher=new n.AES(t),this._prev=new r(o.length),this._cache=new r(""),this._secCache=new r(""),this._decrypt=s,o.copy(this._prev),void(this._mode=e)):new i(e,t,o)}var n=e("./aes"),a=e("./cipherBase"),o=e("inherits");o(i,a),t.exports=i,i.prototype._update=function(e){return this._mode.encrypt(this,e,this._decrypt)},i.prototype._final=function(){this._cipher.scrub()}}).call(this,e("buffer").Buffer)},{"./aes":15,"./cipherBase":18,buffer:9,inherits:151}],31:[function(e,t,r){(function(e){function r(t,r){for(var i=Math.min(t.length,r.length),n=new e(i),a=-1;++a<i;)n.writeUInt8(t[a]^r[a],a);return n}t.exports=r}).call(this,e("buffer").Buffer)},{buffer:9}],32:[function(e,t,r){(function(e){"use strict";r["RSA-SHA224"]=r.sha224WithRSAEncryption={sign:"rsa",hash:"sha224",id:new e("302d300d06096086480165030402040500041c","hex")},r["RSA-SHA256"]=r.sha256WithRSAEncryption={sign:"rsa",hash:"sha256",id:new e("3031300d060960864801650304020105000420","hex")},r["RSA-SHA384"]=r.sha384WithRSAEncryption={sign:"rsa",hash:"sha384",id:new e("3041300d060960864801650304020205000430","hex")},r["RSA-SHA512"]=r.sha512WithRSAEncryption={sign:"rsa",hash:"sha512",id:new e("3051300d060960864801650304020305000440","hex")},r["RSA-SHA1"]={sign:"rsa",hash:"sha1",id:new e("3021300906052b0e03021a05000414","hex")},r["ecdsa-with-SHA1"]={sign:"ecdsa",hash:"sha1",id:new e("","hex")},r.DSA=r["DSA-SHA1"]=r["DSA-SHA"]={sign:"dsa",hash:"sha1",id:new e("","hex")},r["DSA-SHA224"]=r["DSA-WITH-SHA224"]={sign:"dsa",hash:"sha224",id:new e("","hex")},r["DSA-SHA256"]=r["DSA-WITH-SHA256"]={sign:"dsa",hash:"sha256",id:new e("","hex")},r["DSA-SHA384"]=r["DSA-WITH-SHA384"]={sign:"dsa",hash:"sha384",id:new e("","hex")},r["DSA-SHA512"]=r["DSA-WITH-SHA512"]={sign:"dsa",hash:"sha512",id:new e("","hex")},r["DSA-RIPEMD160"]={sign:"dsa",hash:"rmd160",id:new e("","hex")},r["RSA-RIPEMD160"]=r.ripemd160WithRSA={sign:"rsa",hash:"rmd160",id:new e("3021300906052b2403020105000414","hex")},r["RSA-MD5"]=r.md5WithRSAEncryption={sign:"rsa",hash:"md5",id:new e("3020300c06082a864886f70d020505000410","hex")}}).call(this,e("buffer").Buffer)},{buffer:9}],33:[function(e,t,r){(function(t){"use strict";function i(e){return new a(e)}function n(e){return new o(e)}function a(e){f.Writable.call(this);var t=l[e];if(!t)throw new Error("Unknown message digest");this._hashType=t.hash,this._hash=h(t.hash),this._tag=t.id,this._signType=t.sign}function o(e){f.Writable.call(this);var t=l[e];if(!t)throw new Error("Unknown message digest");this._hash=h(t.hash),this._tag=t.id,this._signType=t.sign}var s=e("./sign"),c=e("./verify"),f=e("stream"),d=e("inherits"),u=e("./algos"),h=e("create-hash"),l={};Object.keys(u).forEach(function(e){l[e]=l[e.toLowerCase()]=u[e]}),r.createSign=r.Sign=i,r.createVerify=r.Verify=n,d(a,f.Writable),a.prototype._write=function(e,t,r){this._hash.update(e),r()},a.prototype.update=function(e,r){return"string"==typeof e&&(e=new t(e,r)),this._hash.update(e),this},a.prototype.sign=function(e,r){this.end();var i=this._hash.digest(),n=s(t.concat([this._tag,i]),e,this._hashType,this._signType);return r&&(n=n.toString(r)),n},d(o,f.Writable),o.prototype._write=function(e,t,r){this._hash.update(e),r()},o.prototype.update=function(e,r){return"string"==typeof e&&(e=new t(e,r)),this._hash.update(e),this},o.prototype.verify=function(e,r,i){this.end();var n=this._hash.digest();return"string"==typeof r&&(r=new t(r,i)),c(r,t.concat([this._tag,n]),e,this._signType)}}).call(this,e("buffer").Buffer)},{"./algos":32,"./sign":76,"./verify":77,buffer:9,"create-hash":101,inherits:151,stream:165}],34:[function(e,t,r){"use strict";r["1.3.132.0.10"]="secp256k1",r["1.3.132.0.33"]="p224",r["1.2.840.10045.3.1.1"]="p192",r["1.2.840.10045.3.1.7"]="p256"},{}],35:[function(e,t,r){!function(e,t){"use strict";function r(e,t){if(!e)throw new Error(t||"Assertion failed")}function i(e,t){e.super_=t;var r=function(){};r.prototype=t.prototype,e.prototype=new r,e.prototype.constructor=e}function n(e,t,r){return null!==e&&"object"==typeof e&&Array.isArray(e.words)?e:(this.sign=!1,this.words=null,this.length=0,this.red=null,("le"===t||"be"===t)&&(r=t,t=10),void(null!==e&&this._init(e||0,t||10,r||"be")))}function a(e,t,r){for(var i=0,n=Math.min(e.length,r),a=t;n>a;a++){var o=e.charCodeAt(a)-48;i<<=4,i|=o>=49&&54>=o?o-49+10:o>=17&&22>=o?o-17+10:15&o}return i}function o(e,t,r,i){for(var n=0,a=Math.min(e.length,r),o=t;a>o;o++){var s=e.charCodeAt(o)-48;n*=i,n+=s>=49?s-49+10:s>=17?s-17+10:s}return n}function s(e,t){this.name=e,this.p=new n(t,16),this.n=this.p.bitLength(),this.k=new n(1).ishln(this.n).isub(this.p),this.tmp=this._tmp()}function c(){s.call(this,"k256","ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f")}function f(){s.call(this,"p224","ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001")}function d(){s.call(this,"p192","ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff")}function u(){s.call(this,"25519","7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed")}function h(e){if("string"==typeof e){var t=n._prime(e);this.m=t.p,this.prime=t}else this.m=e,this.prime=null}function l(e){h.call(this,e),this.shift=this.m.bitLength(),this.shift%26!==0&&(this.shift+=26-this.shift%26),this.r=new n(1).ishln(this.shift),this.r2=this.imod(this.r.sqr()),this.rinv=this.r.invm(this.m),this.minv=this.rinv.mul(this.r).isubn(1).div(this.m),this.minv.sign=!0,this.minv=this.minv.mod(this.r)}"object"==typeof e?e.exports=n:t.BN=n,n.BN=n,n.wordSize=26,n.prototype._init=function(e,t,i){if("number"==typeof e)return 0>e&&(this.sign=!0,e=-e),void(67108864>e?(this.words=[67108863&e],this.length=1):(this.words=[67108863&e,e/67108864&67108863],this.length=2));if("object"==typeof e)return this._initArray(e,t,i);"hex"===t&&(t=16),r(t===(0|t)&&t>=2&&36>=t),e=e.toString().replace(/\s+/g,"");var n=0;"-"===e[0]&&n++,16===t?this._parseHex(e,n):this._parseBase(e,t,n),"-"===e[0]&&(this.sign=!0),this.strip()},n.prototype._initArray=function(e,t,i){r("number"==typeof e.length),this.length=Math.ceil(e.length/3),this.words=new Array(this.length);for(var n=0;n<this.length;n++)this.words[n]=0;var a=0;if("be"===i)for(var n=e.length-1,o=0;n>=0;n-=3){var s=e[n]|e[n-1]<<8|e[n-2]<<16;this.words[o]|=s<<a&67108863,this.words[o+1]=s>>>26-a&67108863,a+=24,a>=26&&(a-=26,o++)}else if("le"===i)for(var n=0,o=0;n<e.length;n+=3){var s=e[n]|e[n+1]<<8|e[n+2]<<16;this.words[o]|=s<<a&67108863,this.words[o+1]=s>>>26-a&67108863,a+=24,a>=26&&(a-=26,o++)}return this.strip()},n.prototype._parseHex=function(e,t){this.length=Math.ceil((e.length-t)/6),this.words=new Array(this.length);for(var r=0;r<this.length;r++)this.words[r]=0;for(var i=0,r=e.length-6,n=0;r>=t;r-=6){var o=a(e,r,r+6);this.words[n]|=o<<i&67108863,this.words[n+1]|=o>>>26-i&4194303,i+=24,i>=26&&(i-=26,n++)}if(r+6!==t){var o=a(e,t,r+6);this.words[n]|=o<<i&67108863,this.words[n+1]|=o>>>26-i&4194303}this.strip()},n.prototype._parseBase=function(e,t,r){this.words=[0],this.length=1;for(var i=0,n=1;67108863>=n;n*=t)i++;i--,n=n/t|0;for(var a=e.length-r,s=a%i,c=Math.min(a,a-s)+r,f=0,d=r;c>d;d+=i)f=o(e,d,d+i,t),this.imuln(n),this.words[0]+f<67108864?this.words[0]+=f:this._iaddn(f);if(0!==s){for(var u=1,f=o(e,d,e.length,t),d=0;s>d;d++)u*=t;this.imuln(u),this.words[0]+f<67108864?this.words[0]+=f:this._iaddn(f)}},n.prototype.copy=function(e){e.words=new Array(this.length);for(var t=0;t<this.length;t++)e.words[t]=this.words[t];e.length=this.length,e.sign=this.sign,e.red=this.red},n.prototype.clone=function(){var e=new n(null);return this.copy(e),e},n.prototype.strip=function(){for(;this.length>1&&0===this.words[this.length-1];)this.length--;return this._normSign()},n.prototype._normSign=function(){return 1===this.length&&0===this.words[0]&&(this.sign=!1),this},n.prototype.inspect=function(){return(this.red?"<BN-R: ":"<BN: ")+this.toString(16)+">"};var b=["","0","00","000","0000","00000","000000","0000000","00000000","000000000","0000000000","00000000000","000000000000","0000000000000","00000000000000","000000000000000","0000000000000000","00000000000000000","000000000000000000","0000000000000000000","00000000000000000000","000000000000000000000","0000000000000000000000","00000000000000000000000","000000000000000000000000","0000000000000000000000000"],p=[0,0,25,16,12,11,10,9,8,8,7,7,7,7,6,6,6,6,6,6,6,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5],m=[0,0,33554432,43046721,16777216,48828125,60466176,40353607,16777216,43046721,1e7,19487171,35831808,62748517,7529536,11390625,16777216,24137569,34012224,47045881,64e6,4084101,5153632,6436343,7962624,9765625,11881376,14348907,17210368,20511149,243e5,28629151,33554432,39135393,45435424,52521875,60466176];n.prototype.toString=function(e,t){if(e=e||10,16===e||"hex"===e){for(var i="",n=0,t=0|t||1,a=0,o=0;o<this.length;o++){var s=this.words[o],c=(16777215&(s<<n|a)).toString(16);a=s>>>24-n&16777215,i=0!==a||o!==this.length-1?b[6-c.length]+c+i:c+i,n+=2,n>=26&&(n-=26,o--)}for(0!==a&&(i=a.toString(16)+i);i.length%t!==0;)i="0"+i;return this.sign&&(i="-"+i),i}if(e===(0|e)&&e>=2&&36>=e){var f=p[e],d=m[e],i="",u=this.clone();for(u.sign=!1;0!==u.cmpn(0);){var h=u.modn(d).toString(e);u=u.idivn(d),i=0!==u.cmpn(0)?b[f-h.length]+h+i:h+i}return 0===this.cmpn(0)&&(i="0"+i),this.sign&&(i="-"+i),i}r(!1,"Base should be between 2 and 36")},n.prototype.toJSON=function(){return this.toString(16)},n.prototype.toArray=function(){this.strip();var e=new Array(this.byteLength());e[0]=0;for(var t=this.clone(),r=0;0!==t.cmpn(0);r++){var i=t.andln(255);t.ishrn(8),e[e.length-r-1]=i}return e},n.prototype._countBits=function(e){return e>=33554432?26:e>=16777216?25:e>=8388608?24:e>=4194304?23:e>=2097152?22:e>=1048576?21:e>=524288?20:e>=262144?19:e>=131072?18:e>=65536?17:e>=32768?16:e>=16384?15:e>=8192?14:e>=4096?13:e>=2048?12:e>=1024?11:e>=512?10:e>=256?9:e>=128?8:e>=64?7:e>=32?6:e>=16?5:e>=8?4:e>=4?3:e>=2?2:e>=1?1:0},n.prototype.bitLength=function(){var e=0,t=this.words[this.length-1],e=this._countBits(t);return 26*(this.length-1)+e},n.prototype.byteLength=function(){return Math.ceil(this.bitLength()/8)},n.prototype.neg=function(){if(0===this.cmpn(0))return this.clone();var e=this.clone();return e.sign=!this.sign,e},n.prototype.ior=function(e){for(this.sign=this.sign||e.sign;this.length<e.length;)this.words[this.length++]=0;for(var t=0;t<e.length;t++)this.words[t]=this.words[t]|e.words[t];return this.strip()},n.prototype.or=function(e){return this.length>e.length?this.clone().ior(e):e.clone().ior(this)},n.prototype.iand=function(e){this.sign=this.sign&&e.sign;var t;t=this.length>e.length?e:this;for(var r=0;r<t.length;r++)this.words[r]=this.words[r]&e.words[r];return this.length=t.length,this.strip()},n.prototype.and=function(e){return this.length>e.length?this.clone().iand(e):e.clone().iand(this)},n.prototype.ixor=function(e){this.sign=this.sign||e.sign;var t,r;this.length>e.length?(t=this,r=e):(t=e,r=this);for(var i=0;i<r.length;i++)this.words[i]=t.words[i]^r.words[i];if(this!==t)for(;i<t.length;i++)this.words[i]=t.words[i];return this.length=t.length,this.strip()},n.prototype.xor=function(e){return this.length>e.length?this.clone().ixor(e):e.clone().ixor(this)},n.prototype.setn=function(e,t){r("number"==typeof e&&e>=0);for(var i=e/26|0,n=e%26;this.length<=i;)this.words[this.length++]=0;return this.words[i]=t?this.words[i]|1<<n:this.words[i]&~(1<<n),this.strip()},n.prototype.iadd=function(e){if(this.sign&&!e.sign){this.sign=!1;var t=this.isub(e);return this.sign=!this.sign,this._normSign()}if(!this.sign&&e.sign){e.sign=!1;var t=this.isub(e);return e.sign=!0,t._normSign()}var r,i;this.length>e.length?(r=this,i=e):(r=e,i=this);for(var n=0,a=0;a<i.length;a++){var t=r.words[a]+i.words[a]+n;this.words[a]=67108863&t,n=t>>>26}for(;0!==n&&a<r.length;a++){var t=r.words[a]+n;this.words[a]=67108863&t,n=t>>>26}if(this.length=r.length,0!==n)this.words[this.length]=n,this.length++;else if(r!==this)for(;a<r.length;a++)this.words[a]=r.words[a];

return this},n.prototype.add=function(e){if(e.sign&&!this.sign){e.sign=!1;var t=this.sub(e);return e.sign=!0,t}if(!e.sign&&this.sign){this.sign=!1;var t=e.sub(this);return this.sign=!0,t}return this.length>e.length?this.clone().iadd(e):e.clone().iadd(this)},n.prototype.isub=function(e){if(e.sign){e.sign=!1;var t=this.iadd(e);return e.sign=!0,t._normSign()}if(this.sign)return this.sign=!1,this.iadd(e),this.sign=!0,this._normSign();var r=this.cmp(e);if(0===r)return this.sign=!1,this.length=1,this.words[0]=0,this;var i,n;r>0?(i=this,n=e):(i=e,n=this);for(var a=0,o=0;o<n.length;o++){var t=i.words[o]-n.words[o]+a;a=t>>26,this.words[o]=67108863&t}for(;0!==a&&o<i.length;o++){var t=i.words[o]+a;a=t>>26,this.words[o]=67108863&t}if(0===a&&o<i.length&&i!==this)for(;o<i.length;o++)this.words[o]=i.words[o];return this.length=Math.max(this.length,o),i!==this&&(this.sign=!0),this.strip()},n.prototype.sub=function(e){return this.clone().isub(e)},n.prototype._smallMulTo=function(e,t){t.sign=e.sign!==this.sign,t.length=this.length+e.length;for(var r=0,i=0;i<t.length-1;i++){for(var n=r>>>26,a=67108863&r,o=Math.min(i,e.length-1),s=Math.max(0,i-this.length+1);o>=s;s++){var c=i-s,f=0|this.words[c],d=0|e.words[s],u=f*d,h=67108863&u;n=n+(u/67108864|0)|0,h=h+a|0,a=67108863&h,n=n+(h>>>26)|0}t.words[i]=a,r=n}return 0!==r?t.words[i]=r:t.length--,t.strip()},n.prototype._bigMulTo=function(e,t){t.sign=e.sign!==this.sign,t.length=this.length+e.length;for(var r=0,i=0,n=0;n<t.length-1;n++){var a=i;i=0;for(var o=67108863&r,s=Math.min(n,e.length-1),c=Math.max(0,n-this.length+1);s>=c;c++){var f=n-c,d=0|this.words[f],u=0|e.words[c],h=d*u,l=67108863&h;a=a+(h/67108864|0)|0,l=l+o|0,o=67108863&l,a=a+(l>>>26)|0,i+=a>>>26,a&=67108863}t.words[n]=o,r=a,a=i}return 0!==r?t.words[n]=r:t.length--,t.strip()},n.prototype.mulTo=function(e,t){var r;return r=this.length+e.length<63?this._smallMulTo(e,t):this._bigMulTo(e,t)},n.prototype.mul=function(e){var t=new n(null);return t.words=new Array(this.length+e.length),this.mulTo(e,t)},n.prototype.imul=function(e){if(0===this.cmpn(0)||0===e.cmpn(0))return this.words[0]=0,this.length=1,this;var t=this.length,r=e.length;this.sign=e.sign!==this.sign,this.length=this.length+e.length,this.words[this.length-1]=0;for(var i=this.length-2;i>=0;i--){for(var n=0,a=0,o=Math.min(i,r-1),s=Math.max(0,i-t+1);o>=s;s++){var c=i-s,f=this.words[c],d=e.words[s],u=f*d,h=67108863&u;n+=u/67108864|0,h+=a,a=67108863&h,n+=h>>>26}this.words[i]=a,this.words[i+1]+=n,n=0}for(var n=0,c=1;c<this.length;c++){var l=this.words[c]+n;this.words[c]=67108863&l,n=l>>>26}return this.strip()},n.prototype.imuln=function(e){r("number"==typeof e);for(var t=0,i=0;i<this.length;i++){var n=this.words[i]*e,a=(67108863&n)+(67108863&t);t>>=26,t+=n/67108864|0,t+=a>>>26,this.words[i]=67108863&a}return 0!==t&&(this.words[i]=t,this.length++),this},n.prototype.sqr=function(){return this.mul(this)},n.prototype.isqr=function(){return this.mul(this)},n.prototype.ishln=function(e){r("number"==typeof e&&e>=0);var t=e%26,i=(e-t)/26,n=67108863>>>26-t<<26-t;if(0!==t){for(var a=0,o=0;o<this.length;o++){var s=this.words[o]&n,c=this.words[o]-s<<t;this.words[o]=c|a,a=s>>>26-t}a&&(this.words[o]=a,this.length++)}if(0!==i){for(var o=this.length-1;o>=0;o--)this.words[o+i]=this.words[o];for(var o=0;i>o;o++)this.words[o]=0;this.length+=i}return this.strip()},n.prototype.ishrn=function(e,t,i){r("number"==typeof e&&e>=0),t=t?(t-t%26)/26:0;var n=e%26,a=Math.min((e-n)/26,this.length),o=67108863^67108863>>>n<<n,s=i;if(t-=a,t=Math.max(0,t),s){for(var c=0;a>c;c++)s.words[c]=this.words[c];s.length=a}if(0===a);else if(this.length>a){this.length-=a;for(var c=0;c<this.length;c++)this.words[c]=this.words[c+a]}else this.words[0]=0,this.length=1;for(var f=0,c=this.length-1;c>=0&&(0!==f||c>=t);c--){var d=this.words[c];this.words[c]=f<<26-n|d>>>n,f=d&o}return s&&0!==f&&(s.words[s.length++]=f),0===this.length&&(this.words[0]=0,this.length=1),this.strip(),i?{hi:this,lo:s}:this},n.prototype.shln=function(e){return this.clone().ishln(e)},n.prototype.shrn=function(e){return this.clone().ishrn(e)},n.prototype.testn=function(e){r("number"==typeof e&&e>=0);var t=e%26,i=(e-t)/26,n=1<<t;if(this.length<=i)return!1;var a=this.words[i];return!!(a&n)},n.prototype.imaskn=function(e){r("number"==typeof e&&e>=0);var t=e%26,i=(e-t)/26;if(r(!this.sign,"imaskn works only with positive numbers"),0!==t&&i++,this.length=Math.min(i,this.length),0!==t){var n=67108863^67108863>>>t<<t;this.words[this.length-1]&=n}return this.strip()},n.prototype.maskn=function(e){return this.clone().imaskn(e)},n.prototype.iaddn=function(e){return r("number"==typeof e),0>e?this.isubn(-e):this.sign?1===this.length&&this.words[0]<e?(this.words[0]=e-this.words[0],this.sign=!1,this):(this.sign=!1,this.isubn(e),this.sign=!0,this):this._iaddn(e)},n.prototype._iaddn=function(e){this.words[0]+=e;for(var t=0;t<this.length&&this.words[t]>=67108864;t++)this.words[t]-=67108864,t===this.length-1?this.words[t+1]=1:this.words[t+1]++;return this.length=Math.max(this.length,t+1),this},n.prototype.isubn=function(e){if(r("number"==typeof e),0>e)return this.iaddn(-e);if(this.sign)return this.sign=!1,this.iaddn(e),this.sign=!0,this;this.words[0]-=e;for(var t=0;t<this.length&&this.words[t]<0;t++)this.words[t]+=67108864,this.words[t+1]-=1;return this.strip()},n.prototype.addn=function(e){return this.clone().iaddn(e)},n.prototype.subn=function(e){return this.clone().isubn(e)},n.prototype.iabs=function(){return this.sign=!1,this},n.prototype.abs=function(){return this.clone().iabs()},n.prototype._ishlnsubmul=function(e,t,i){var n,a=e.length+i;if(this.words.length<a){for(var o=new Array(a),n=0;n<this.length;n++)o[n]=this.words[n];this.words=o}else n=this.length;for(this.length=Math.max(this.length,a);n<this.length;n++)this.words[n]=0;for(var s=0,n=0;n<e.length;n++){var c=this.words[n+i]+s,f=e.words[n]*t;c-=67108863&f,s=(c>>26)-(f/67108864|0),this.words[n+i]=67108863&c}for(;n<this.length-i;n++){var c=this.words[n+i]+s;s=c>>26,this.words[n+i]=67108863&c}if(0===s)return this.strip();r(-1===s),s=0;for(var n=0;n<this.length;n++){var c=-this.words[n]+s;s=c>>26,this.words[n]=67108863&c}return this.sign=!0,this.strip()},n.prototype._wordDiv=function(e,t){for(var r=this.length-e.length,i=this.clone(),a=e,o=a.words[a.length-1],r=0;33554432>o;r++)o<<=1;0!==r&&(a=a.shln(r),i.ishln(r),o=a.words[a.length-1]);var s,c=i.length-a.length;if("mod"!==t){s=new n(null),s.length=c+1,s.words=new Array(s.length);for(var f=0;f<s.length;f++)s.words[f]=0}var d=i.clone()._ishlnsubmul(a,1,c);d.sign||(i=d,s&&(s.words[c]=1));for(var u=c-1;u>=0;u--){var h=67108864*i.words[a.length+u]+i.words[a.length+u-1];for(h=Math.min(h/o|0,67108863),i._ishlnsubmul(a,h,u);i.sign;)h--,i.sign=!1,i._ishlnsubmul(a,1,u),i.sign=!i.sign;s&&(s.words[u]=h)}return s&&s.strip(),i.strip(),"div"!==t&&0!==r&&i.ishrn(r),{div:s?s:null,mod:i}},n.prototype.divmod=function(e,t){if(r(0!==e.cmpn(0)),this.sign&&!e.sign){var i,a,o=this.neg().divmod(e,t);return"mod"!==t&&(i=o.div.neg()),"div"!==t&&(a=0===o.mod.cmpn(0)?o.mod:e.sub(o.mod)),{div:i,mod:a}}if(!this.sign&&e.sign){var i,o=this.divmod(e.neg(),t);return"mod"!==t&&(i=o.div.neg()),{div:i,mod:o.mod}}return this.sign&&e.sign?this.neg().divmod(e.neg(),t):e.length>this.length||this.cmp(e)<0?{div:new n(0),mod:this}:1===e.length?"div"===t?{div:this.divn(e.words[0]),mod:null}:"mod"===t?{div:null,mod:new n(this.modn(e.words[0]))}:{div:this.divn(e.words[0]),mod:new n(this.modn(e.words[0]))}:this._wordDiv(e,t)},n.prototype.div=function(e){return this.divmod(e,"div").div},n.prototype.mod=function(e){return this.divmod(e,"mod").mod},n.prototype.divRound=function(e){var t=this.divmod(e);if(0===t.mod.cmpn(0))return t.div;var r=t.div.sign?t.mod.isub(e):t.mod,i=e.shrn(1),n=e.andln(1),a=r.cmp(i);return 0>a||1===n&&0===a?t.div:t.div.sign?t.div.isubn(1):t.div.iaddn(1)},n.prototype.modn=function(e){r(67108863>=e);for(var t=(1<<26)%e,i=0,n=this.length-1;n>=0;n--)i=(t*i+this.words[n])%e;return i},n.prototype.idivn=function(e){r(67108863>=e);for(var t=0,i=this.length-1;i>=0;i--){var n=this.words[i]+67108864*t;this.words[i]=n/e|0,t=n%e}return this.strip()},n.prototype.divn=function(e){return this.clone().idivn(e)},n.prototype._egcd=function(e,t){r(!t.sign),r(0!==t.cmpn(0));var i=this,a=t.clone();i=i.sign?i.mod(t):i.clone();for(var o=new n(0);a.isEven();)a.ishrn(1);for(var s=a.clone();i.cmpn(1)>0&&a.cmpn(1)>0;){for(;i.isEven();)i.ishrn(1),e.isEven()?e.ishrn(1):e.iadd(s).ishrn(1);for(;a.isEven();)a.ishrn(1),o.isEven()?o.ishrn(1):o.iadd(s).ishrn(1);i.cmp(a)>=0?(i.isub(a),e.isub(o)):(a.isub(i),o.isub(e))}return 0===i.cmpn(1)?e:o},n.prototype.gcd=function(e){if(0===this.cmpn(0))return e.clone();if(0===e.cmpn(0))return this.clone();var t=this.clone(),r=e.clone();t.sign=!1,r.sign=!1;for(var i=0;t.isEven()&&r.isEven();i++)t.ishrn(1),r.ishrn(1);for(;t.isEven();)t.ishrn(1);do{for(;r.isEven();)r.ishrn(1);if(t.cmp(r)<0){var n=t;t=r,r=n}t.isub(t.div(r).mul(r))}while(0!==t.cmpn(0)&&0!==r.cmpn(0));return 0===t.cmpn(0)?r.ishln(i):t.ishln(i)},n.prototype.invm=function(e){return this._egcd(new n(1),e).mod(e)},n.prototype.isEven=function(){return 0===(1&this.words[0])},n.prototype.isOdd=function(){return 1===(1&this.words[0])},n.prototype.andln=function(e){return this.words[0]&e},n.prototype.bincn=function(e){r("number"==typeof e);var t=e%26,i=(e-t)/26,n=1<<t;if(this.length<=i){for(var a=this.length;i+1>a;a++)this.words[a]=0;return this.words[i]|=n,this.length=i+1,this}for(var o=n,a=i;0!==o&&a<this.length;a++){var s=this.words[a];s+=o,o=s>>>26,s&=67108863,this.words[a]=s}return 0!==o&&(this.words[a]=o,this.length++),this},n.prototype.cmpn=function(e){var t=0>e;if(t&&(e=-e),this.sign&&!t)return-1;if(!this.sign&&t)return 1;e&=67108863,this.strip();var r;if(this.length>1)r=1;else{var i=this.words[0];r=i===e?0:e>i?-1:1}return this.sign&&(r=-r),r},n.prototype.cmp=function(e){if(this.sign&&!e.sign)return-1;if(!this.sign&&e.sign)return 1;var t=this.ucmp(e);return this.sign?-t:t},n.prototype.ucmp=function(e){if(this.length>e.length)return 1;if(this.length<e.length)return-1;for(var t=0,r=this.length-1;r>=0;r--){var i=this.words[r],n=e.words[r];if(i!==n){n>i?t=-1:i>n&&(t=1);break}}return t},n.red=function(e){return new h(e)},n.prototype.toRed=function(e){return r(!this.red,"Already a number in reduction context"),r(!this.sign,"red works only with positives"),e.convertTo(this)._forceRed(e)},n.prototype.fromRed=function(){return r(this.red,"fromRed works only with numbers in reduction context"),this.red.convertFrom(this)},n.prototype._forceRed=function(e){return this.red=e,this},n.prototype.forceRed=function(e){return r(!this.red,"Already a number in reduction context"),this._forceRed(e)},n.prototype.redAdd=function(e){return r(this.red,"redAdd works only with red numbers"),this.red.add(this,e)},n.prototype.redIAdd=function(e){return r(this.red,"redIAdd works only with red numbers"),this.red.iadd(this,e)},n.prototype.redSub=function(e){return r(this.red,"redSub works only with red numbers"),this.red.sub(this,e)},n.prototype.redISub=function(e){return r(this.red,"redISub works only with red numbers"),this.red.isub(this,e)},n.prototype.redShl=function(e){return r(this.red,"redShl works only with red numbers"),this.red.shl(this,e)},n.prototype.redMul=function(e){return r(this.red,"redMul works only with red numbers"),this.red._verify2(this,e),this.red.mul(this,e)},n.prototype.redIMul=function(e){return r(this.red,"redMul works only with red numbers"),this.red._verify2(this,e),this.red.imul(this,e)},n.prototype.redSqr=function(){return r(this.red,"redSqr works only with red numbers"),this.red._verify1(this),this.red.sqr(this)},n.prototype.redISqr=function(){return r(this.red,"redISqr works only with red numbers"),this.red._verify1(this),this.red.isqr(this)},n.prototype.redSqrt=function(){return r(this.red,"redSqrt works only with red numbers"),this.red._verify1(this),this.red.sqrt(this)},n.prototype.redInvm=function(){return r(this.red,"redInvm works only with red numbers"),this.red._verify1(this),this.red.invm(this)},n.prototype.redNeg=function(){return r(this.red,"redNeg works only with red numbers"),this.red._verify1(this),this.red.neg(this)},n.prototype.redPow=function(e){return r(this.red&&!e.red,"redPow(normalNum)"),this.red._verify1(this),this.red.pow(this,e)};var g={k256:null,p224:null,p192:null,p25519:null};s.prototype._tmp=function(){var e=new n(null);return e.words=new Array(Math.ceil(this.n/13)),e},s.prototype.ireduce=function(e){var t,r=e;do{var i=r.ishrn(this.n,0,this.tmp);r=this.imulK(i.hi),r=r.iadd(i.lo),t=r.bitLength()}while(t>this.n);var n=t<this.n?-1:r.cmp(this.p);return 0===n?(r.words[0]=0,r.length=1):n>0?r.isub(this.p):r.strip(),r},s.prototype.imulK=function(e){return e.imul(this.k)},i(c,s),c.prototype.imulK=function(e){e.words[e.length]=0,e.words[e.length+1]=0,e.length+=2;for(var t,r=0,i=0;i<e.length;i++){var n=e.words[i];t=64*n,r+=977*n,t+=r/67108864|0,r&=67108863,e.words[i]=r,r=t}return 0===e.words[e.length-1]&&(e.length--,0===e.words[e.length-1]&&e.length--),e},i(f,s),i(d,s),i(u,s),u.prototype.imulK=function(e){for(var t=0,r=0;r<e.length;r++){var i=19*e.words[r]+t,n=67108863&i;i>>>=26,e.words[r]=n,t=i}return 0!==t&&(e.words[e.length++]=t),e},n._prime=function v(e){if(g[e])return g[e];var v;if("k256"===e)v=new c;else if("p224"===e)v=new f;else if("p192"===e)v=new d;else{if("p25519"!==e)throw new Error("Unknown prime "+e);v=new u}return g[e]=v,v},h.prototype._verify1=function(e){r(!e.sign,"red works only with positives"),r(e.red,"red works only with red numbers")},h.prototype._verify2=function(e,t){r(!e.sign&&!t.sign,"red works only with positives"),r(e.red&&e.red===t.red,"red works only with red numbers")},h.prototype.imod=function(e){return this.prime?this.prime.ireduce(e)._forceRed(this):e.mod(this.m)._forceRed(this)},h.prototype.neg=function(e){var t=e.clone();return t.sign=!t.sign,t.iadd(this.m)._forceRed(this)},h.prototype.add=function(e,t){this._verify2(e,t);var r=e.add(t);return r.cmp(this.m)>=0&&r.isub(this.m),r._forceRed(this)},h.prototype.iadd=function(e,t){this._verify2(e,t);var r=e.iadd(t);return r.cmp(this.m)>=0&&r.isub(this.m),r},h.prototype.sub=function(e,t){this._verify2(e,t);var r=e.sub(t);return r.cmpn(0)<0&&r.iadd(this.m),r._forceRed(this)},h.prototype.isub=function(e,t){this._verify2(e,t);var r=e.isub(t);return r.cmpn(0)<0&&r.iadd(this.m),r},h.prototype.shl=function(e,t){return this._verify1(e),this.imod(e.shln(t))},h.prototype.imul=function(e,t){return this._verify2(e,t),this.imod(e.imul(t))},h.prototype.mul=function(e,t){return this._verify2(e,t),this.imod(e.mul(t))},h.prototype.isqr=function(e){return this.imul(e,e)},h.prototype.sqr=function(e){return this.mul(e,e)},h.prototype.sqrt=function(e){if(0===e.cmpn(0))return e.clone();var t=this.m.andln(3);if(r(t%2===1),3===t){var i=this.m.add(new n(1)).ishrn(2),a=this.pow(e,i);return a}for(var o=this.m.subn(1),s=0;0!==o.cmpn(0)&&0===o.andln(1);)s++,o.ishrn(1);r(0!==o.cmpn(0));var c=new n(1).toRed(this),f=c.redNeg(),d=this.m.subn(1).ishrn(1),u=this.m.bitLength();for(u=new n(2*u*u).toRed(this);0!==this.pow(u,d).cmp(f);)u.redIAdd(f);for(var h=this.pow(u,o),a=this.pow(e,o.addn(1).ishrn(1)),l=this.pow(e,o),b=s;0!==l.cmp(c);){for(var p=l,m=0;0!==p.cmp(c);m++)p=p.redSqr();r(b>m);var g=this.pow(h,new n(1).ishln(b-m-1));a=a.redMul(g),h=g.redSqr(),l=l.redMul(h),b=m}return a},h.prototype.invm=function(e){var t=e._egcd(new n(1),this.m);return t.sign?(t.sign=!1,this.imod(t).redNeg()):this.imod(t)},h.prototype.pow=function(e,t){for(var r=[],i=t.clone();0!==i.cmpn(0);)r.push(i.andln(1)),i.ishrn(1);for(var n=e,a=0;a<r.length&&0===r[a];a++,n=this.sqr(n));if(++a<r.length)for(var i=this.sqr(n);a<r.length;a++,i=this.sqr(i))0!==r[a]&&(n=this.mul(n,i));return n},h.prototype.convertTo=function(e){return e.clone()},h.prototype.convertFrom=function(e){var t=e.clone();return t.red=null,t},n.mont=function(e){return new l(e)},i(l,h),l.prototype.convertTo=function(e){return this.imod(e.shln(this.shift))},l.prototype.convertFrom=function(e){var t=this.imod(e.mul(this.rinv));return t.red=null,t},l.prototype.imul=function(e,t){if(0===e.cmpn(0)||0===t.cmpn(0))return e.words[0]=0,e.length=1,e;var r=e.imul(t),i=r.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m),n=r.isub(i).ishrn(this.shift),a=n;return n.cmp(this.m)>=0?a=n.isub(this.m):n.cmpn(0)<0&&(a=n.iadd(this.m)),a._forceRed(this)},l.prototype.mul=function(e,t){if(0===e.cmpn(0)||0===t.cmpn(0))return new n(0)._forceRed(this);var r=e.mul(t),i=r.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m),a=r.isub(i).ishrn(this.shift),o=a;return a.cmp(this.m)>=0?o=a.isub(this.m):a.cmpn(0)<0&&(o=a.iadd(this.m)),o._forceRed(this)},l.prototype.invm=function(e){var t=this.imod(e.invm(this.m).mul(this.r2));return t._forceRed(this)}}("undefined"==typeof t||t,this)},{}],36:[function(e,t,r){(function(r){function i(e){var t=a(e),r=t.toRed(o.mont(e.modulus)).redPow(new o(e.publicExponent)).fromRed();return{blinder:r,unblinder:t.invm(e.modulus)}}function n(e,t){var n=i(t),a=t.modulus.byteLength(),s=(o.mont(t.modulus),new o(e).mul(n.blinder).mod(t.modulus)),c=s.toRed(o.mont(t.prime1)),f=s.toRed(o.mont(t.prime2)),d=t.coefficient,u=t.prime1,h=t.prime2,l=c.redPow(t.exponent1),b=f.redPow(t.exponent2);l=l.fromRed(),b=b.fromRed();var p=l.isub(b).imul(d).mod(u);p.imul(h),b.iadd(p);var m=new r(b.imul(n.unblinder).mod(t.modulus).toArray());if(m.length<a){var g=new r(a-m.length);g.fill(0),m=r.concat([g,m],a)}return m}function a(e){for(var t=e.modulus.byteLength(),r=new o(s(t));r.cmp(e.modulus)>=0||!r.mod(e.prime1)||!r.mod(e.prime2);)r=new o(s(t));return r}var o=e("bn.js"),s=e("randombytes");t.exports=n,n.getr=a}).call(this,e("buffer").Buffer)},{"bn.js":35,buffer:9,randombytes:149}],37:[function(e,t,r){var i=r;i.version=e("../package.json").version,i.utils=e("./elliptic/utils"),i.rand=e("brorand"),i.hmacDRBG=e("./elliptic/hmac-drbg"),i.curve=e("./elliptic/curve"),i.curves=e("./elliptic/curves"),i.ec=e("./elliptic/ec")},{"../package.json":56,"./elliptic/curve":40,"./elliptic/curves":43,"./elliptic/ec":44,"./elliptic/hmac-drbg":47,"./elliptic/utils":48,brorand:49}],38:[function(e,t,r){function i(e,t){this.type=e,this.p=new a(t.p,16),this.red=t.prime?a.red(t.prime):a.mont(this.p),this.zero=new a(0).toRed(this.red),this.one=new a(1).toRed(this.red),this.two=new a(2).toRed(this.red),this.n=t.n&&new a(t.n,16),this.g=t.g&&this.pointFromJSON(t.g,t.gRed),this._wnafT1=new Array(4),this._wnafT2=new Array(4),this._wnafT3=new Array(4),this._wnafT4=new Array(4)}function n(e,t){this.curve=e,this.type=t,this.precomputed=null}var a=e("bn.js"),o=e("../../elliptic"),s=o.utils.getNAF,c=o.utils.getJSF,f=o.utils.assert;t.exports=i,i.prototype.point=function(){throw new Error("Not implemented")},i.prototype.validate=function(e){throw new Error("Not implemented")},i.prototype._fixedNafMul=function(e,t){var r=e._getDoubles(),i=s(t,1),n=(1<<r.step+1)-(r.step%2===0?2:1);n/=3;for(var a=[],o=0;o<i.length;o+=r.step){for(var c=0,t=o+r.step-1;t>=o;t--)c=(c<<1)+i[t];a.push(c)}for(var f=this.jpoint(null,null,null),d=this.jpoint(null,null,null),u=n;u>0;u--){for(var o=0;o<a.length;o++){var c=a[o];c===u?d=d.mixedAdd(r.points[o]):c===-u&&(d=d.mixedAdd(r.points[o].neg()))}f=f.add(d)}return f.toP()},i.prototype._wnafMul=function(e,t){var r=4,i=e._getNAFPoints(r);r=i.wnd;for(var n=i.points,a=s(t,r),o=this.jpoint(null,null,null),c=a.length-1;c>=0;c--){for(var t=0;c>=0&&0===a[c];c--)t++;if(c>=0&&t++,o=o.dblp(t),0>c)break;var d=a[c];f(0!==d),o="affine"===e.type?o.mixedAdd(d>0?n[d-1>>1]:n[-d-1>>1].neg()):o.add(d>0?n[d-1>>1]:n[-d-1>>1].neg())}return"affine"===e.type?o.toP():o},i.prototype._wnafMulAdd=function(e,t,r,i){for(var n=this._wnafT1,a=this._wnafT2,o=this._wnafT3,f=0,d=0;i>d;d++){var u=t[d],h=u._getNAFPoints(e);n[d]=h.wnd,a[d]=h.points}for(var d=i-1;d>=1;d-=2){var l=d-1,b=d;if(1===n[l]&&1===n[b]){var p=[t[l],null,null,t[b]];0===t[l].y.cmp(t[b].y)?(p[1]=t[l].add(t[b]),p[2]=t[l].toJ().mixedAdd(t[b].neg())):0===t[l].y.cmp(t[b].y.redNeg())?(p[1]=t[l].toJ().mixedAdd(t[b]),p[2]=t[l].add(t[b].neg())):(p[1]=t[l].toJ().mixedAdd(t[b]),p[2]=t[l].toJ().mixedAdd(t[b].neg()));var m=[-3,-1,-5,-7,0,7,5,1,3],g=c(r[l],r[b]);f=Math.max(g[0].length,f),o[l]=new Array(f),o[b]=new Array(f);for(var v=0;f>v;v++){var y=0|g[0][v],w=0|g[1][v];o[l][v]=m[3*(y+1)+(w+1)],o[b][v]=0,a[l]=p}}else o[l]=s(r[l],n[l]),o[b]=s(r[b],n[b]),f=Math.max(o[l].length,f),f=Math.max(o[b].length,f)}for(var _=this.jpoint(null,null,null),S=this._wnafT4,d=f;d>=0;d--){for(var k=0;d>=0;){for(var E=!0,v=0;i>v;v++)S[v]=0|o[v][d],0!==S[v]&&(E=!1);if(!E)break;k++,d--}if(d>=0&&k++,_=_.dblp(k),0>d)break;for(var v=0;i>v;v++){var u,x=S[v];0!==x&&(x>0?u=a[v][x-1>>1]:0>x&&(u=a[v][-x-1>>1].neg()),_="affine"===u.type?_.mixedAdd(u):_.add(u))}}for(var d=0;i>d;d++)a[d]=null;return _.toP()},i.BasePoint=n,n.prototype.validate=function(){return this.curve.validate(this)},n.prototype.precompute=function(e,t){if(this.precomputed)return this;var r={doubles:null,naf:null,beta:null};return r.naf=this._getNAFPoints(8),r.doubles=this._getDoubles(4,e),r.beta=this._getBeta(),this.precomputed=r,this},n.prototype._getDoubles=function(e,t){if(this.precomputed&&this.precomputed.doubles)return this.precomputed.doubles;for(var r=[this],i=this,n=0;t>n;n+=e){for(var a=0;e>a;a++)i=i.dbl();r.push(i)}return{step:e,points:r}},n.prototype._getNAFPoints=function(e){if(this.precomputed&&this.precomputed.naf)return this.precomputed.naf;for(var t=[this],r=(1<<e)-1,i=1===r?null:this.dbl(),n=1;r>n;n++)t[n]=t[n-1].add(i);return{wnd:e,points:t}},n.prototype._getBeta=function(){return null},n.prototype.dblp=function(e){for(var t=this,r=0;e>r;r++)t=t.dbl();return t}},{"../../elliptic":37,"bn.js":35}],39:[function(e,t,r){function i(e){this.twisted=1!=e.a,this.mOneA=this.twisted&&-1==e.a,this.extended=this.mOneA,f.call(this,"mont",e),this.a=new s(e.a,16).mod(this.red.m).toRed(this.red),this.c=new s(e.c,16).toRed(this.red),this.c2=this.c.redSqr(),this.d=new s(e.d,16).toRed(this.red),this.dd=this.d.redAdd(this.d),d(!this.twisted||0===this.c.fromRed().cmpn(1)),this.oneC=1==e.c}function n(e,t,r,i,n){f.BasePoint.call(this,e,"projective"),null===t&&null===r&&null===i?(this.x=this.curve.zero,this.y=this.curve.one,this.z=this.curve.one,this.t=this.curve.zero,this.zOne=!0):(this.x=new s(t,16),this.y=new s(r,16),this.z=i?new s(i,16):this.curve.one,this.t=n&&new s(n,16),this.x.red||(this.x=this.x.toRed(this.curve.red)),this.y.red||(this.y=this.y.toRed(this.curve.red)),this.z.red||(this.z=this.z.toRed(this.curve.red)),this.t&&!this.t.red&&(this.t=this.t.toRed(this.curve.red)),this.zOne=this.z===this.curve.one,this.curve.extended&&!this.t&&(this.t=this.x.redMul(this.y),this.zOne||(this.t=this.t.redMul(this.z.redInvm()))))}var a=e("../curve"),o=e("../../elliptic"),s=e("bn.js"),c=e("inherits"),f=a.base,d=(o.utils.getNAF,o.utils.assert);c(i,f),t.exports=i,i.prototype._mulA=function(e){return this.mOneA?e.redNeg():this.a.redMul(e)},i.prototype._mulC=function(e){return this.oneC?e:this.c.redMul(e)},i.prototype.point=function(e,t,r,i){return new n(this,e,t,r,i)},i.prototype.jpoint=function(e,t,r,i){return this.point(e,t,r,i)},i.prototype.pointFromJSON=function(e){return n.fromJSON(this,e)},i.prototype.pointFromX=function(e,t){t=new s(t,16),t.red||(t=t.toRed(this.red));var r=t.redSqr(),i=this.c2.redSub(this.a.redMul(r)),n=this.one.redSub(this.c2.redMul(this.d).redMul(r)),o=i.redMul(n.redInvm()).redSqrt(),c=o.fromRed().isOdd();return(e&&!c||!e&&c)&&(o=o.redNeg()),this.point(t,o,a.one)},i.prototype.validate=function(e){if(e.isInfinity())return!0;e.normalize();var t=e.x.redSqr(),r=e.y.redSqr(),i=t.redMul(this.a).redAdd(r),n=this.c2.redMul(this.one.redAdd(this.d.redMul(t).redMul(r)));return 0===i.cmp(n)},c(n,f.BasePoint),n.fromJSON=function(e,t){return new n(e,t[0],t[1],t[2])},n.prototype.inspect=function(){return this.isInfinity()?"<EC Point Infinity>":"<EC Point x: "+this.x.fromRed().toString(16,2)+" y: "+this.y.fromRed().toString(16,2)+" z: "+this.z.fromRed().toString(16,2)+">"},n.prototype.isInfinity=function(){return 0===this.x.cmpn(0)&&0===this.y.cmp(this.z)},n.prototype._extDbl=function(){var e=this.x.redSqr(),t=this.y.redSqr(),r=this.z.redSqr();r=r.redIAdd(r);var i=this.curve._mulA(e),n=this.x.redAdd(this.y).redSqr().redISub(e).redISub(t),a=i.redAdd(t),o=a.redSub(r),s=i.redSub(t),c=n.redMul(o),f=a.redMul(s),d=n.redMul(s),u=o.redMul(a);return this.curve.point(c,f,u,d)},n.prototype._projDbl=function(){var e=this.x.redAdd(this.y).redSqr(),t=this.x.redSqr(),r=this.y.redSqr();if(this.curve.twisted){var i=this.curve._mulA(t),n=i.redAdd(r);if(this.zOne)var a=e.redSub(t).redSub(r).redMul(n.redSub(this.curve.two)),o=n.redMul(i.redSub(r)),s=n.redSqr().redSub(n).redSub(n);else var c=this.z.redSqr(),f=n.redSub(c).redISub(c),a=e.redSub(t).redISub(r).redMul(f),o=n.redMul(i.redSub(r)),s=n.redMul(f)}else var i=t.redAdd(r),c=this.curve._mulC(redMul(this.z)).redSqr(),f=i.redSub(c).redSub(c),a=this.curve._mulC(e.redISub(i)).redMul(f),o=this.curve._mulC(i).redMul(t.redISub(r)),s=i.redMul(f);return this.curve.point(a,o,s)},n.prototype.dbl=function(){return this.isInfinity()?this:this.curve.extended?this._extDbl():this._projDbl()},n.prototype._extAdd=function(e){var t=this.y.redSub(this.x).redMul(e.y.redSub(e.x)),r=this.y.redAdd(this.x).redMul(e.y.redAdd(e.x)),i=this.t.redMul(this.curve.dd).redMul(e.t),n=this.z.redMul(e.z.redAdd(e.z)),a=r.redSub(t),o=n.redSub(i),s=n.redAdd(i),c=r.redAdd(t),f=a.redMul(o),d=s.redMul(c),u=a.redMul(c),h=o.redMul(s);return this.curve.point(f,d,h,u)},n.prototype._projAdd=function(e){var t=this.z.redMul(e.z),r=t.redSqr(),i=this.x.redMul(e.x),n=this.y.redMul(e.y),a=this.curve.d.redMul(i).redMul(n),o=r.redSub(a),s=r.redAdd(a),c=this.x.redAdd(this.y).redMul(e.x.redAdd(e.y)).redISub(i).redISub(n),f=t.redMul(o).redMul(c);if(this.curve.twisted)var d=t.redMul(s).redMul(n.redSub(this.curve._mulA(i))),u=o.redMul(s);else var d=t.redMul(s).redMul(n.redSub(i)),u=this.curve._mulC(o).redMul(s);return this.curve.point(f,d,u)},n.prototype.add=function(e){return this.isInfinity()?e:e.isInfinity()?this:this.curve.extended?this._extAdd(e):this._projAdd(e)},n.prototype.mul=function(e){return this.precomputed&&this.precomputed.doubles?this.curve._fixedNafMul(this,e):this.curve._wnafMul(this,e)},n.prototype.mulAdd=function(e,t,r){return this.curve._wnafMulAdd(1,[this,t],[e,r],2)},n.prototype.normalize=function(){if(this.zOne)return this;var e=this.z.redInvm();return this.x=this.x.redMul(e),this.y=this.y.redMul(e),this.t&&(this.t=this.t.redMul(e)),this.z=this.curve.one,this.zOne=!0,this},n.prototype.neg=function(){return this.curve.point(this.x.redNeg(),this.y,this.z,this.t&&this.t.redNeg())},n.prototype.getX=function(){return this.normalize(),this.x.fromRed()},n.prototype.getY=function(){return this.normalize(),this.y.fromRed()},n.prototype.toP=n.prototype.normalize,n.prototype.mixedAdd=n.prototype.add},{"../../elliptic":37,"../curve":40,"bn.js":35,inherits:151}],40:[function(e,t,r){var i=r;i.base=e("./base"),i["short"]=e("./short"),i.mont=e("./mont"),i.edwards=e("./edwards")},{"./base":38,"./edwards":39,"./mont":41,"./short":42}],41:[function(e,t,r){function i(e){f.call(this,"mont",e),this.a=new s(e.a,16).toRed(this.red),this.b=new s(e.b,16).toRed(this.red),this.i4=new s(4).toRed(this.red).redInvm(),this.two=new s(2).toRed(this.red),this.a24=this.i4.redMul(this.a.redAdd(this.two))}function n(e,t,r){f.BasePoint.call(this,e,"projective"),null===t&&null===r?(this.x=this.curve.one,this.z=this.curve.zero):(this.x=new s(t,16),this.z=new s(r,16),this.x.red||(this.x=this.x.toRed(this.curve.red)),this.z.red||(this.z=this.z.toRed(this.curve.red)))}{var a=e("../curve"),o=e("../../elliptic"),s=e("bn.js"),c=e("inherits"),f=a.base;o.utils.getNAF,o.utils.assert}c(i,f),t.exports=i,i.prototype.point=function(e,t){return new n(this,e,t)},i.prototype.pointFromJSON=function(e){return n.fromJSON(this,e)},i.prototype.validate=function(e){var t=e.normalize().x,r=t.redSqr(),i=r.redMul(t).redAdd(r.redMul(this.a)).redAdd(t),n=i.redSqrt();return 0===n.redSqr().cmp(i)},c(n,f.BasePoint),n.prototype.precompute=function(){},n.fromJSON=function(e,t){return new n(e,t[0],t[1]||e.one)},n.prototype.inspect=function(){return this.isInfinity()?"<EC Point Infinity>":"<EC Point x: "+this.x.fromRed().toString(16,2)+" z: "+this.z.fromRed().toString(16,2)+">"},n.prototype.isInfinity=function(){return 0===this.z.cmpn(0)},n.prototype.dbl=function(){var e=this.x.redAdd(this.z),t=e.redSqr(),r=this.x.redSub(this.z),i=r.redSqr(),n=t.redSub(i),a=t.redMul(i),o=n.redMul(i.redAdd(this.curve.a24.redMul(n)));return this.curve.point(a,o)},n.prototype.add=function(e){throw new Error("Not supported on Montgomery curve")},n.prototype.diffAdd=function(e,t){var r=this.x.redAdd(this.z),i=this.x.redSub(this.z),n=e.x.redAdd(e.z),a=e.x.redSub(e.z),o=a.redMul(r),s=n.redMul(i),c=t.z.redMul(o.redAdd(s).redSqr()),f=t.x.redMul(o.redISub(s).redSqr());return this.curve.point(c,f)},n.prototype.mul=function(e){for(var t=e.clone(),r=this,i=this.curve.point(null,null),n=this,a=[];0!==t.cmpn(0);t.ishrn(1))a.push(t.andln(1));for(var o=a.length-1;o>=0;o--)0===a[o]?(r=r.diffAdd(i,n),i=i.dbl()):(i=r.diffAdd(i,n),r=r.dbl());return i},n.prototype.mulAdd=function(){throw new Error("Not supported on Montgomery curve")},n.prototype.normalize=function(){return this.x=this.x.redMul(this.z.redInvm()),this.z=this.curve.one,this},n.prototype.getX=function(){return this.normalize(),this.x.fromRed()}},{"../../elliptic":37,"../curve":40,"bn.js":35,inherits:151}],42:[function(e,t,r){function i(e){d.call(this,"short",e),this.a=new c(e.a,16).toRed(this.red),this.b=new c(e.b,16).toRed(this.red),this.tinv=this.two.redInvm(),this.zeroA=0===this.a.fromRed().cmpn(0),this.threeA=0===this.a.fromRed().sub(this.p).cmpn(-3),this.endo=this._getEndomorphism(e),this._endoWnafT1=new Array(4),this._endoWnafT2=new Array(4)}function n(e,t,r,i){d.BasePoint.call(this,e,"affine"),null===t&&null===r?(this.x=null,this.y=null,this.inf=!0):(this.x=new c(t,16),this.y=new c(r,16),i&&(this.x.forceRed(this.curve.red),this.y.forceRed(this.curve.red)),this.x.red||(this.x=this.x.toRed(this.curve.red)),this.y.red||(this.y=this.y.toRed(this.curve.red)),this.inf=!1)}function a(e,t,r,i){d.BasePoint.call(this,e,"jacobian"),null===t&&null===r&&null===i?(this.x=this.curve.one,this.y=this.curve.one,this.z=new c(0)):(this.x=new c(t,16),this.y=new c(r,16),this.z=new c(i,16)),this.x.red||(this.x=this.x.toRed(this.curve.red)),this.y.red||(this.y=this.y.toRed(this.curve.red)),this.z.red||(this.z=this.z.toRed(this.curve.red)),this.zOne=this.z===this.curve.one}var o=e("../curve"),s=e("../../elliptic"),c=e("bn.js"),f=e("inherits"),d=o.base,u=(s.utils.getNAF,s.utils.assert);f(i,d),t.exports=i,i.prototype._getEndomorphism=function(e){if(this.zeroA&&this.g&&this.n&&1===this.p.modn(3)){var t,r;if(e.beta)t=new c(e.beta,16).toRed(this.red);else{var i=this._getEndoRoots(this.p);t=i[0].cmp(i[1])<0?i[0]:i[1],t=t.toRed(this.red)}if(e.lambda)r=new c(e.lambda,16);else{var n=this._getEndoRoots(this.n);0===this.g.mul(n[0]).x.cmp(this.g.x.redMul(t))?r=n[0]:(r=n[1],u(0===this.g.mul(r).x.cmp(this.g.x.redMul(t))))}var a;return a=e.basis?e.basis.map(function(e){return{a:new c(e.a,16),b:new c(e.b,16)}}):this._getEndoBasis(r),{beta:t,lambda:r,basis:a}}},i.prototype._getEndoRoots=function(e){var t=e===this.p?this.red:c.mont(e),r=new c(2).toRed(t).redInvm(),i=r.redNeg(),n=(new c(1).toRed(t),new c(3).toRed(t).redNeg().redSqrt().redMul(r)),a=i.redAdd(n).fromRed(),o=i.redSub(n).fromRed();return[a,o]},i.prototype._getEndoBasis=function(e){for(var t,r,i,n,a,o,s,f=this.n.shrn(Math.floor(this.n.bitLength()/2)),d=e,u=this.n.clone(),h=new c(1),l=new c(0),b=new c(0),p=new c(1),m=0;0!==d.cmpn(0);){var g=u.div(d),v=u.sub(g.mul(d)),y=b.sub(g.mul(h)),w=p.sub(g.mul(l));if(!i&&v.cmp(f)<0)t=s.neg(),r=h,i=v.neg(),n=y;else if(i&&2===++m)break;s=v,u=d,d=v,b=h,h=y,p=l,l=w}a=v.neg(),o=y;var _=i.sqr().add(n.sqr()),S=a.sqr().add(o.sqr());return S.cmp(_)>=0&&(a=t,o=r),i.sign&&(i=i.neg(),n=n.neg()),a.sign&&(a=a.neg(),o=o.neg()),[{a:i,b:n},{a:a,b:o}]},i.prototype._endoSplit=function(e){
var t=this.endo.basis,r=t[0],i=t[1],n=i.b.mul(e).divRound(this.n),a=r.b.neg().mul(e).divRound(this.n),o=n.mul(r.a),s=a.mul(i.a),c=n.mul(r.b),f=a.mul(i.b),d=e.sub(o).sub(s),u=c.add(f).neg();return{k1:d,k2:u}},i.prototype.point=function(e,t,r){return new n(this,e,t,r)},i.prototype.pointFromX=function(e,t){t=new c(t,16),t.red||(t=t.toRed(this.red));var r=t.redSqr().redMul(t).redIAdd(t.redMul(this.a)).redIAdd(this.b),i=r.redSqrt(),n=i.fromRed().isOdd();return(e&&!n||!e&&n)&&(i=i.redNeg()),this.point(t,i)},i.prototype.jpoint=function(e,t,r){return new a(this,e,t,r)},i.prototype.pointFromJSON=function(e,t){return n.fromJSON(this,e,t)},i.prototype.validate=function(e){if(e.inf)return!0;var t=e.x,r=e.y,i=this.a.redMul(t),n=t.redSqr().redMul(t).redIAdd(i).redIAdd(this.b);return 0===r.redSqr().redISub(n).cmpn(0)},i.prototype._endoWnafMulAdd=function(e,t){for(var r=this._endoWnafT1,i=this._endoWnafT2,n=0;n<e.length;n++){var a=this._endoSplit(t[n]),o=e[n],s=o._getBeta();a.k1.sign&&(a.k1.sign=!a.k1.sign,o=o.neg(!0)),a.k2.sign&&(a.k2.sign=!a.k2.sign,s=s.neg(!0)),r[2*n]=o,r[2*n+1]=s,i[2*n]=a.k1,i[2*n+1]=a.k2}for(var c=this._wnafMulAdd(1,r,i,2*n),f=0;2*n>f;f++)r[f]=null,i[f]=null;return c},f(n,d.BasePoint),n.prototype._getBeta=function(){function e(e){return i.point(e.x.redMul(i.endo.beta),e.y)}if(this.curve.endo){var t=this.precomputed;if(t&&t.beta)return t.beta;var r=this.curve.point(this.x.redMul(this.curve.endo.beta),this.y);if(t){var i=this.curve;t.beta=r,r.precomputed={beta:null,naf:t.naf&&{wnd:t.naf.wnd,points:t.naf.points.map(e)},doubles:t.doubles&&{step:t.doubles.step,points:t.doubles.points.map(e)}}}return r}},n.prototype.toJSON=function(){return this.precomputed?[this.x,this.y,this.precomputed&&{doubles:this.precomputed.doubles&&{step:this.precomputed.doubles.step,points:this.precomputed.doubles.points.slice(1)},naf:this.precomputed.naf&&{wnd:this.precomputed.naf.wnd,points:this.precomputed.naf.points.slice(1)}}]:[this.x,this.y]},n.fromJSON=function(e,t,r){function i(t){return e.point(t[0],t[1],r)}"string"==typeof t&&(t=JSON.parse(t));var n=e.point(t[0],t[1],r);if(!t[2])return n;var a=t[2];return n.precomputed={beta:null,doubles:a.doubles&&{step:a.doubles.step,points:[n].concat(a.doubles.points.map(i))},naf:a.naf&&{wnd:a.naf.wnd,points:[n].concat(a.naf.points.map(i))}},n},n.prototype.inspect=function(){return this.isInfinity()?"<EC Point Infinity>":"<EC Point x: "+this.x.fromRed().toString(16,2)+" y: "+this.y.fromRed().toString(16,2)+">"},n.prototype.isInfinity=function(){return this.inf},n.prototype.add=function(e){if(this.inf)return e;if(e.inf)return this;if(this.eq(e))return this.dbl();if(this.neg().eq(e))return this.curve.point(null,null);if(0===this.x.cmp(e.x))return this.curve.point(null,null);var t=this.y.redSub(e.y);0!==t.cmpn(0)&&(t=t.redMul(this.x.redSub(e.x).redInvm()));var r=t.redSqr().redISub(this.x).redISub(e.x),i=t.redMul(this.x.redSub(r)).redISub(this.y);return this.curve.point(r,i)},n.prototype.dbl=function(){if(this.inf)return this;var e=this.y.redAdd(this.y);if(0===e.cmpn(0))return this.curve.point(null,null);var t=this.curve.a,r=this.x.redSqr(),i=e.redInvm(),n=r.redAdd(r).redIAdd(r).redIAdd(t).redMul(i),a=n.redSqr().redISub(this.x.redAdd(this.x)),o=n.redMul(this.x.redSub(a)).redISub(this.y);return this.curve.point(a,o)},n.prototype.getX=function(){return this.x.fromRed()},n.prototype.getY=function(){return this.y.fromRed()},n.prototype.mul=function(e){return e=new c(e,16),this.precomputed&&this.precomputed.doubles?this.curve._fixedNafMul(this,e):this.curve.endo?this.curve._endoWnafMulAdd([this],[e]):this.curve._wnafMul(this,e)},n.prototype.mulAdd=function(e,t,r){var i=[this,t],n=[e,r];return this.curve.endo?this.curve._endoWnafMulAdd(i,n):this.curve._wnafMulAdd(1,i,n,2)},n.prototype.eq=function(e){return this===e||this.inf===e.inf&&(this.inf||0===this.x.cmp(e.x)&&0===this.y.cmp(e.y))},n.prototype.neg=function(e){function t(e){return e.neg()}if(this.inf)return this;var r=this.curve.point(this.x,this.y.redNeg());if(e&&this.precomputed){var i=this.precomputed;r.precomputed={naf:i.naf&&{wnd:i.naf.wnd,points:i.naf.points.map(t)},doubles:i.doubles&&{step:i.doubles.step,points:i.doubles.points.map(t)}}}return r},n.prototype.toJ=function(){if(this.inf)return this.curve.jpoint(null,null,null);var e=this.curve.jpoint(this.x,this.y,this.curve.one);return e},f(a,d.BasePoint),a.prototype.toP=function(){if(this.isInfinity())return this.curve.point(null,null);var e=this.z.redInvm(),t=e.redSqr(),r=this.x.redMul(t),i=this.y.redMul(t).redMul(e);return this.curve.point(r,i)},a.prototype.neg=function(){return this.curve.jpoint(this.x,this.y.redNeg(),this.z)},a.prototype.add=function(e){if(this.isInfinity())return e;if(e.isInfinity())return this;var t=e.z.redSqr(),r=this.z.redSqr(),i=this.x.redMul(t),n=e.x.redMul(r),a=this.y.redMul(t.redMul(e.z)),o=e.y.redMul(r.redMul(this.z)),s=i.redSub(n),c=a.redSub(o);if(0===s.cmpn(0))return 0!==c.cmpn(0)?this.curve.jpoint(null,null,null):this.dbl();var f=s.redSqr(),d=f.redMul(s),u=i.redMul(f),h=c.redSqr().redIAdd(d).redISub(u).redISub(u),l=c.redMul(u.redISub(h)).redISub(a.redMul(d)),b=this.z.redMul(e.z).redMul(s);return this.curve.jpoint(h,l,b)},a.prototype.mixedAdd=function(e){if(this.isInfinity())return e.toJ();if(e.isInfinity())return this;var t=this.z.redSqr(),r=this.x,i=e.x.redMul(t),n=this.y,a=e.y.redMul(t).redMul(this.z),o=r.redSub(i),s=n.redSub(a);if(0===o.cmpn(0))return 0!==s.cmpn(0)?this.curve.jpoint(null,null,null):this.dbl();var c=o.redSqr(),f=c.redMul(o),d=r.redMul(c),u=s.redSqr().redIAdd(f).redISub(d).redISub(d),h=s.redMul(d.redISub(u)).redISub(n.redMul(f)),l=this.z.redMul(o);return this.curve.jpoint(u,h,l)},a.prototype.dblp=function(e){if(0===e)return this;if(this.isInfinity())return this;if(!e)return this.dbl();if(this.curve.zeroA||this.curve.threeA){for(var t=this,r=0;e>r;r++)t=t.dbl();return t}for(var i=this.curve.a,n=this.curve.tinv,a=this.x,o=this.y,s=this.z,c=s.redSqr().redSqr(),f=o.redAdd(o),r=0;e>r;r++){var d=a.redSqr(),u=f.redSqr(),h=u.redSqr(),l=d.redAdd(d).redIAdd(d).redIAdd(i.redMul(c)),b=a.redMul(u),p=l.redSqr().redISub(b.redAdd(b)),m=b.redISub(p),g=l.redMul(m);g=g.redIAdd(g).redISub(h);var v=f.redMul(s);e>r+1&&(c=c.redMul(h)),a=p,s=v,f=g}return this.curve.jpoint(a,f.redMul(n),s)},a.prototype.dbl=function(){return this.isInfinity()?this:this.curve.zeroA?this._zeroDbl():this.curve.threeA?this._threeDbl():this._dbl()},a.prototype._zeroDbl=function(){if(this.zOne){var e=this.x.redSqr(),t=this.y.redSqr(),r=t.redSqr(),i=this.x.redAdd(t).redSqr().redISub(e).redISub(r);i=i.redIAdd(i);var n=e.redAdd(e).redIAdd(e),a=n.redSqr().redISub(i).redISub(i),o=r.redIAdd(r);o=o.redIAdd(o),o=o.redIAdd(o);var s=a,c=n.redMul(i.redISub(a)).redISub(o),f=this.y.redAdd(this.y)}else{var d=this.x.redSqr(),u=this.y.redSqr(),h=u.redSqr(),l=this.x.redAdd(u).redSqr().redISub(d).redISub(h);l=l.redIAdd(l);var b=d.redAdd(d).redIAdd(d),p=b.redSqr(),m=h.redIAdd(h);m=m.redIAdd(m),m=m.redIAdd(m);var s=p.redISub(l).redISub(l),c=b.redMul(l.redISub(s)).redISub(m),f=this.y.redMul(this.z);f=f.redIAdd(f)}return this.curve.jpoint(s,c,f)},a.prototype._threeDbl=function(){if(this.zOne){var e=this.x.redSqr(),t=this.y.redSqr(),r=t.redSqr(),i=this.x.redAdd(t).redSqr().redISub(e).redISub(r);i=i.redIAdd(i);var n=e.redAdd(e).redIAdd(e).redIAdd(this.curve.a),a=n.redSqr().redISub(i).redISub(i),o=a,s=r.redIAdd(r);s=s.redIAdd(s),s=s.redIAdd(s);var c=n.redMul(i.redISub(a)).redISub(s),f=this.y.redAdd(this.y)}else{var d=this.z.redSqr(),u=this.y.redSqr(),h=this.x.redMul(u),l=this.x.redSub(d).redMul(this.x.redAdd(d));l=l.redAdd(l).redIAdd(l);var b=h.redIAdd(h);b=b.redIAdd(b);var p=b.redAdd(b),o=l.redSqr().redISub(p),f=this.y.redAdd(this.z).redSqr().redISub(u).redISub(d),m=u.redSqr();m=m.redIAdd(m),m=m.redIAdd(m),m=m.redIAdd(m);var c=l.redMul(b.redISub(o)).redISub(m)}return this.curve.jpoint(o,c,f)},a.prototype._dbl=function(){var e=this.curve.a,t=(this.curve.tinv,this.x),r=this.y,i=this.z,n=i.redSqr().redSqr(),a=t.redSqr(),o=r.redSqr(),s=a.redAdd(a).redIAdd(a).redIAdd(e.redMul(n)),c=t.redAdd(t);c=c.redIAdd(c);var f=c.redMul(o),d=s.redSqr().redISub(f.redAdd(f)),u=f.redISub(d),h=o.redSqr();h=h.redIAdd(h),h=h.redIAdd(h),h=h.redIAdd(h);var l=s.redMul(u).redISub(h),b=r.redAdd(r).redMul(i);return this.curve.jpoint(d,l,b)},a.prototype.trpl=function(){if(!this.curve.zeroA)return this.dbl().add(this);var e=this.x.redSqr(),t=this.y.redSqr(),r=this.z.redSqr(),i=t.redSqr(),n=e.redAdd(e).redIAdd(e),a=n.redSqr(),o=this.x.redAdd(t).redSqr().redISub(e).redISub(i);o=o.redIAdd(o),o=o.redAdd(o).redIAdd(o),o=o.redISub(a);var s=o.redSqr(),c=i.redIAdd(i);c=c.redIAdd(c),c=c.redIAdd(c),c=c.redIAdd(c);var f=n.redIAdd(o).redSqr().redISub(a).redISub(s).redISub(c),d=t.redMul(f);d=d.redIAdd(d),d=d.redIAdd(d);var u=this.x.redMul(s).redISub(d);u=u.redIAdd(u),u=u.redIAdd(u);var h=this.y.redMul(f.redMul(c.redISub(f)).redISub(o.redMul(s)));h=h.redIAdd(h),h=h.redIAdd(h),h=h.redIAdd(h);var l=this.z.redAdd(o).redSqr().redISub(r).redISub(s);return this.curve.jpoint(u,h,l)},a.prototype.mul=function(e,t){return e=new c(e,t),this.curve._wnafMul(this,e)},a.prototype.eq=function(e){if("affine"===e.type)return this.eq(e.toJ());if(this===e)return!0;var t=this.z.redSqr(),r=e.z.redSqr();if(0!==this.x.redMul(r).redISub(e.x.redMul(t)).cmpn(0))return!1;var i=t.redMul(this.z),n=r.redMul(e.z);return 0===this.y.redMul(n).redISub(e.y.redMul(i)).cmpn(0)},a.prototype.inspect=function(){return this.isInfinity()?"<EC JPoint Infinity>":"<EC JPoint x: "+this.x.toString(16,2)+" y: "+this.y.toString(16,2)+" z: "+this.z.toString(16,2)+">"},a.prototype.isInfinity=function(){return 0===this.z.cmpn(0)}},{"../../elliptic":37,"../curve":40,"bn.js":35,inherits:151}],43:[function(e,t,r){function i(e){this.curve="short"===e.type?new s.curve["short"](e):"edwards"===e.type?new s.curve.edwards(e):new s.curve.mont(e),this.g=this.curve.g,this.n=this.curve.n,this.hash=e.hash,c(this.g.validate(),"Invalid curve"),c(this.g.mul(this.n).isInfinity(),"Invalid curve, G*N != O")}function n(e,t){Object.defineProperty(a,e,{configurable:!0,enumerable:!0,get:function(){var r=new i(t);return Object.defineProperty(a,e,{configurable:!0,enumerable:!0,value:r}),r}})}var a=r,o=e("hash.js"),s=(e("bn.js"),e("../elliptic")),c=s.utils.assert;a.PresetCurve=i,n("p192",{type:"short",prime:"p192",p:"ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff",a:"ffffffff ffffffff ffffffff fffffffe ffffffff fffffffc",b:"64210519 e59c80e7 0fa7e9ab 72243049 feb8deec c146b9b1",n:"ffffffff ffffffff ffffffff 99def836 146bc9b1 b4d22831",hash:o.sha256,gRed:!1,g:["188da80e b03090f6 7cbf20eb 43a18800 f4ff0afd 82ff1012","07192b95 ffc8da78 631011ed 6b24cdd5 73f977a1 1e794811"]}),n("p224",{type:"short",prime:"p224",p:"ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001",a:"ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff fffffffe",b:"b4050a85 0c04b3ab f5413256 5044b0b7 d7bfd8ba 270b3943 2355ffb4",n:"ffffffff ffffffff ffffffff ffff16a2 e0b8f03e 13dd2945 5c5c2a3d",hash:o.sha256,gRed:!1,g:["b70e0cbd 6bb4bf7f 321390b9 4a03c1d3 56c21122 343280d6 115c1d21","bd376388 b5f723fb 4c22dfe6 cd4375a0 5a074764 44d58199 85007e34"]}),n("p256",{type:"short",prime:null,p:"ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff",a:"ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffc",b:"5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6 3bce3c3e 27d2604b",n:"ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84 f3b9cac2 fc632551",hash:o.sha256,gRed:!1,g:["6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296","4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5"]}),n("curve25519",{type:"mont",prime:"p25519",p:"7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed",a:"76d06",b:"0",n:"1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed",hash:o.sha256,gRed:!1,g:["9"]}),n("ed25519",{type:"edwards",prime:"p25519",p:"7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed",a:"-1",c:"1",d:"52036cee2b6ffe73 8cc740797779e898 00700a4d4141d8ab 75eb4dca135978a3",n:"1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed",hash:o.sha256,gRed:!1,g:["216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a","6666666666666666666666666666666666666666666666666666666666666658"]}),n("secp256k1",{type:"short",prime:"k256",p:"ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f",a:"0",b:"7",n:"ffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b bfd25e8c d0364141",h:"1",hash:o.sha256,beta:"7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee",lambda:"5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72",basis:[{a:"3086d221a7d46bcde86c90e49284eb15",b:"-e4437ed6010e88286f547fa90abfe4c3"},{a:"114ca50f7a8e2f3f657c1108d9d44cfd8",b:"3086d221a7d46bcde86c90e49284eb15"}],gRed:!1,g:["79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",{doubles:{step:4,points:[["e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a","f7e3507399e595929db99f34f57937101296891e44d23f0be1f32cce69616821"],["8282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508","11f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf"],["175e159f728b865a72f99cc6c6fc846de0b93833fd2222ed73fce5b551e5b739","d3506e0d9e3c79eba4ef97a51ff71f5eacb5955add24345c6efa6ffee9fed695"],["363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640","4e273adfc732221953b445397f3363145b9a89008199ecb62003c7f3bee9de9"],["8b4b5f165df3c2be8c6244b5b745638843e4a781a15bcd1b69f79a55dffdf80c","4aad0a6f68d308b4b3fbd7813ab0da04f9e336546162ee56b3eff0c65fd4fd36"],["723cbaa6e5db996d6bf771c00bd548c7b700dbffa6c0e77bcb6115925232fcda","96e867b5595cc498a921137488824d6e2660a0653779494801dc069d9eb39f5f"],["eebfa4d493bebf98ba5feec812c2d3b50947961237a919839a533eca0e7dd7fa","5d9a8ca3970ef0f269ee7edaf178089d9ae4cdc3a711f712ddfd4fdae1de8999"],["100f44da696e71672791d0a09b7bde459f1215a29b3c03bfefd7835b39a48db0","cdd9e13192a00b772ec8f3300c090666b7ff4a18ff5195ac0fbd5cd62bc65a09"],["e1031be262c7ed1b1dc9227a4a04c017a77f8d4464f3b3852c8acde6e534fd2d","9d7061928940405e6bb6a4176597535af292dd419e1ced79a44f18f29456a00d"],["feea6cae46d55b530ac2839f143bd7ec5cf8b266a41d6af52d5e688d9094696d","e57c6b6c97dce1bab06e4e12bf3ecd5c981c8957cc41442d3155debf18090088"],["da67a91d91049cdcb367be4be6ffca3cfeed657d808583de33fa978bc1ec6cb1","9bacaa35481642bc41f463f7ec9780e5dec7adc508f740a17e9ea8e27a68be1d"],["53904faa0b334cdda6e000935ef22151ec08d0f7bb11069f57545ccc1a37b7c0","5bc087d0bc80106d88c9eccac20d3c1c13999981e14434699dcb096b022771c8"],["8e7bcd0bd35983a7719cca7764ca906779b53a043a9b8bcaeff959f43ad86047","10b7770b2a3da4b3940310420ca9514579e88e2e47fd68b3ea10047e8460372a"],["385eed34c1cdff21e6d0818689b81bde71a7f4f18397e6690a841e1599c43862","283bebc3e8ea23f56701de19e9ebf4576b304eec2086dc8cc0458fe5542e5453"],["6f9d9b803ecf191637c73a4413dfa180fddf84a5947fbc9c606ed86c3fac3a7","7c80c68e603059ba69b8e2a30e45c4d47ea4dd2f5c281002d86890603a842160"],["3322d401243c4e2582a2147c104d6ecbf774d163db0f5e5313b7e0e742d0e6bd","56e70797e9664ef5bfb019bc4ddaf9b72805f63ea2873af624f3a2e96c28b2a0"],["85672c7d2de0b7da2bd1770d89665868741b3f9af7643397721d74d28134ab83","7c481b9b5b43b2eb6374049bfa62c2e5e77f17fcc5298f44c8e3094f790313a6"],["948bf809b1988a46b06c9f1919413b10f9226c60f668832ffd959af60c82a0a","53a562856dcb6646dc6b74c5d1c3418c6d4dff08c97cd2bed4cb7f88d8c8e589"],["6260ce7f461801c34f067ce0f02873a8f1b0e44dfc69752accecd819f38fd8e8","bc2da82b6fa5b571a7f09049776a1ef7ecd292238051c198c1a84e95b2b4ae17"],["e5037de0afc1d8d43d8348414bbf4103043ec8f575bfdc432953cc8d2037fa2d","4571534baa94d3b5f9f98d09fb990bddbd5f5b03ec481f10e0e5dc841d755bda"],["e06372b0f4a207adf5ea905e8f1771b4e7e8dbd1c6a6c5b725866a0ae4fce725","7a908974bce18cfe12a27bb2ad5a488cd7484a7787104870b27034f94eee31dd"],["213c7a715cd5d45358d0bbf9dc0ce02204b10bdde2a3f58540ad6908d0559754","4b6dad0b5ae462507013ad06245ba190bb4850f5f36a7eeddff2c27534b458f2"],["4e7c272a7af4b34e8dbb9352a5419a87e2838c70adc62cddf0cc3a3b08fbd53c","17749c766c9d0b18e16fd09f6def681b530b9614bff7dd33e0b3941817dcaae6"],["fea74e3dbe778b1b10f238ad61686aa5c76e3db2be43057632427e2840fb27b6","6e0568db9b0b13297cf674deccb6af93126b596b973f7b77701d3db7f23cb96f"],["76e64113f677cf0e10a2570d599968d31544e179b760432952c02a4417bdde39","c90ddf8dee4e95cf577066d70681f0d35e2a33d2b56d2032b4b1752d1901ac01"],["c738c56b03b2abe1e8281baa743f8f9a8f7cc643df26cbee3ab150242bcbb891","893fb578951ad2537f718f2eacbfbbbb82314eef7880cfe917e735d9699a84c3"],["d895626548b65b81e264c7637c972877d1d72e5f3a925014372e9f6588f6c14b","febfaa38f2bc7eae728ec60818c340eb03428d632bb067e179363ed75d7d991f"],["b8da94032a957518eb0f6433571e8761ceffc73693e84edd49150a564f676e03","2804dfa44805a1e4d7c99cc9762808b092cc584d95ff3b511488e4e74efdf6e7"],["e80fea14441fb33a7d8adab9475d7fab2019effb5156a792f1a11778e3c0df5d","eed1de7f638e00771e89768ca3ca94472d155e80af322ea9fcb4291b6ac9ec78"],["a301697bdfcd704313ba48e51d567543f2a182031efd6915ddc07bbcc4e16070","7370f91cfb67e4f5081809fa25d40f9b1735dbf7c0a11a130c0d1a041e177ea1"],["90ad85b389d6b936463f9d0512678de208cc330b11307fffab7ac63e3fb04ed4","e507a3620a38261affdcbd9427222b839aefabe1582894d991d4d48cb6ef150"],["8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da","662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82"],["e4f3fb0176af85d65ff99ff9198c36091f48e86503681e3e6686fd5053231e11","1e63633ad0ef4f1c1661a6d0ea02b7286cc7e74ec951d1c9822c38576feb73bc"],["8c00fa9b18ebf331eb961537a45a4266c7034f2f0d4e1d0716fb6eae20eae29e","efa47267fea521a1a9dc343a3736c974c2fadafa81e36c54e7d2a4c66702414b"],["e7a26ce69dd4829f3e10cec0a9e98ed3143d084f308b92c0997fddfc60cb3e41","2a758e300fa7984b471b006a1aafbb18d0a6b2c0420e83e20e8a9421cf2cfd51"],["b6459e0ee3662ec8d23540c223bcbdc571cbcb967d79424f3cf29eb3de6b80ef","67c876d06f3e06de1dadf16e5661db3c4b3ae6d48e35b2ff30bf0b61a71ba45"],["d68a80c8280bb840793234aa118f06231d6f1fc67e73c5a5deda0f5b496943e8","db8ba9fff4b586d00c4b1f9177b0e28b5b0e7b8f7845295a294c84266b133120"],["324aed7df65c804252dc0270907a30b09612aeb973449cea4095980fc28d3d5d","648a365774b61f2ff130c0c35aec1f4f19213b0c7e332843967224af96ab7c84"],["4df9c14919cde61f6d51dfdbe5fee5dceec4143ba8d1ca888e8bd373fd054c96","35ec51092d8728050974c23a1d85d4b5d506cdc288490192ebac06cad10d5d"],["9c3919a84a474870faed8a9c1cc66021523489054d7f0308cbfc99c8ac1f98cd","ddb84f0f4a4ddd57584f044bf260e641905326f76c64c8e6be7e5e03d4fc599d"],["6057170b1dd12fdf8de05f281d8e06bb91e1493a8b91d4cc5a21382120a959e5","9a1af0b26a6a4807add9a2daf71df262465152bc3ee24c65e899be932385a2a8"],["a576df8e23a08411421439a4518da31880cef0fba7d4df12b1a6973eecb94266","40a6bf20e76640b2c92b97afe58cd82c432e10a7f514d9f3ee8be11ae1b28ec8"],["7778a78c28dec3e30a05fe9629de8c38bb30d1f5cf9a3a208f763889be58ad71","34626d9ab5a5b22ff7098e12f2ff580087b38411ff24ac563b513fc1fd9f43ac"],["928955ee637a84463729fd30e7afd2ed5f96274e5ad7e5cb09eda9c06d903ac","c25621003d3f42a827b78a13093a95eeac3d26efa8a8d83fc5180e935bcd091f"],["85d0fef3ec6db109399064f3a0e3b2855645b4a907ad354527aae75163d82751","1f03648413a38c0be29d496e582cf5663e8751e96877331582c237a24eb1f962"],["ff2b0dce97eece97c1c9b6041798b85dfdfb6d8882da20308f5404824526087e","493d13fef524ba188af4c4dc54d07936c7b7ed6fb90e2ceb2c951e01f0c29907"],["827fbbe4b1e880ea9ed2b2e6301b212b57f1ee148cd6dd28780e5e2cf856e241","c60f9c923c727b0b71bef2c67d1d12687ff7a63186903166d605b68baec293ec"],["eaa649f21f51bdbae7be4ae34ce6e5217a58fdce7f47f9aa7f3b58fa2120e2b3","be3279ed5bbbb03ac69a80f89879aa5a01a6b965f13f7e59d47a5305ba5ad93d"],["e4a42d43c5cf169d9391df6decf42ee541b6d8f0c9a137401e23632dda34d24f","4d9f92e716d1c73526fc99ccfb8ad34ce886eedfa8d8e4f13a7f7131deba9414"],["1ec80fef360cbdd954160fadab352b6b92b53576a88fea4947173b9d4300bf19","aeefe93756b5340d2f3a4958a7abbf5e0146e77f6295a07b671cdc1cc107cefd"],["146a778c04670c2f91b00af4680dfa8bce3490717d58ba889ddb5928366642be","b318e0ec3354028add669827f9d4b2870aaa971d2f7e5ed1d0b297483d83efd0"],["fa50c0f61d22e5f07e3acebb1aa07b128d0012209a28b9776d76a8793180eef9","6b84c6922397eba9b72cd2872281a68a5e683293a57a213b38cd8d7d3f4f2811"],["da1d61d0ca721a11b1a5bf6b7d88e8421a288ab5d5bba5220e53d32b5f067ec2","8157f55a7c99306c79c0766161c91e2966a73899d279b48a655fba0f1ad836f1"],["a8e282ff0c9706907215ff98e8fd416615311de0446f1e062a73b0610d064e13","7f97355b8db81c09abfb7f3c5b2515888b679a3e50dd6bd6cef7c73111f4cc0c"],["174a53b9c9a285872d39e56e6913cab15d59b1fa512508c022f382de8319497c","ccc9dc37abfc9c1657b4155f2c47f9e6646b3a1d8cb9854383da13ac079afa73"],["959396981943785c3d3e57edf5018cdbe039e730e4918b3d884fdff09475b7ba","2e7e552888c331dd8ba0386a4b9cd6849c653f64c8709385e9b8abf87524f2fd"],["d2a63a50ae401e56d645a1153b109a8fcca0a43d561fba2dbb51340c9d82b151","e82d86fb6443fcb7565aee58b2948220a70f750af484ca52d4142174dcf89405"],["64587e2335471eb890ee7896d7cfdc866bacbdbd3839317b3436f9b45617e073","d99fcdd5bf6902e2ae96dd6447c299a185b90a39133aeab358299e5e9faf6589"],["8481bde0e4e4d885b3a546d3e549de042f0aa6cea250e7fd358d6c86dd45e458","38ee7b8cba5404dd84a25bf39cecb2ca900a79c42b262e556d64b1b59779057e"],["13464a57a78102aa62b6979ae817f4637ffcfed3c4b1ce30bcd6303f6caf666b","69be159004614580ef7e433453ccb0ca48f300a81d0942e13f495a907f6ecc27"],["bc4a9df5b713fe2e9aef430bcc1dc97a0cd9ccede2f28588cada3a0d2d83f366","d3a81ca6e785c06383937adf4b798caa6e8a9fbfa547b16d758d666581f33c1"],["8c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa","40a30463a3305193378fedf31f7cc0eb7ae784f0451cb9459e71dc73cbef9482"],["8ea9666139527a8c1dd94ce4f071fd23c8b350c5a4bb33748c4ba111faccae0","620efabbc8ee2782e24e7c0cfb95c5d735b783be9cf0f8e955af34a30e62b945"],["dd3625faef5ba06074669716bbd3788d89bdde815959968092f76cc4eb9a9787","7a188fa3520e30d461da2501045731ca941461982883395937f68d00c644a573"],["f710d79d9eb962297e4f6232b40e8f7feb2bc63814614d692c12de752408221e","ea98e67232d3b3295d3b535532115ccac8612c721851617526ae47a9c77bfc82"]]},naf:{wnd:7,points:[["f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9","388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"],["2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4","d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6"],["5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc","6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da"],["acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe","cc338921b0a7d9fd64380971763b61e9add888a4375f8e0f05cc262ac64f9c37"],["774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb","d984a032eb6b5e190243dd56d7b7b365372db1e2dff9d6a8301d74c9c953c61b"],["f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8","ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81"],["d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e","581e2872a86c72a683842ec228cc6defea40af2bd896d3a5c504dc9ff6a26b58"],["defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34","4211ab0694635168e997b0ead2a93daeced1f4a04a95c0f6cfb199f69e56eb77"],["2b4ea0a797a443d293ef5cff444f4979f06acfebd7e86d277475656138385b6c","85e89bc037945d93b343083b5a1c86131a01f60c50269763b570c854e5c09b7a"],["352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5","321eb4075348f534d59c18259dda3e1f4a1b3b2e71b1039c67bd3d8bcf81998c"],["2fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f","2de1068295dd865b64569335bd5dd80181d70ecfc882648423ba76b532b7d67"],["9248279b09b4d68dab21a9b066edda83263c3d84e09572e269ca0cd7f5453714","73016f7bf234aade5d1aa71bdea2b1ff3fc0de2a887912ffe54a32ce97cb3402"],["daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729","a69dce4a7d6c98e8d4a1aca87ef8d7003f83c230f3afa726ab40e52290be1c55"],["c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db","2119a460ce326cdc76c45926c982fdac0e106e861edf61c5a039063f0e0e6482"],["6a245bf6dc698504c89a20cfded60853152b695336c28063b61c65cbd269e6b4","e022cf42c2bd4a708b3f5126f16a24ad8b33ba48d0423b6efd5e6348100d8a82"],["1697ffa6fd9de627c077e3d2fe541084ce13300b0bec1146f95ae57f0d0bd6a5","b9c398f186806f5d27561506e4557433a2cf15009e498ae7adee9d63d01b2396"],["605bdb019981718b986d0f07e834cb0d9deb8360ffb7f61df982345ef27a7479","2972d2de4f8d20681a78d93ec96fe23c26bfae84fb14db43b01e1e9056b8c49"],["62d14dab4150bf497402fdc45a215e10dcb01c354959b10cfe31c7e9d87ff33d","80fc06bd8cc5b01098088a1950eed0db01aa132967ab472235f5642483b25eaf"],["80c60ad0040f27dade5b4b06c408e56b2c50e9f56b9b8b425e555c2f86308b6f","1c38303f1cc5c30f26e66bad7fe72f70a65eed4cbe7024eb1aa01f56430bd57a"],["7a9375ad6167ad54aa74c6348cc54d344cc5dc9487d847049d5eabb0fa03c8fb","d0e3fa9eca8726909559e0d79269046bdc59ea10c70ce2b02d499ec224dc7f7"],["d528ecd9b696b54c907a9ed045447a79bb408ec39b68df504bb51f459bc3ffc9","eecf41253136e5f99966f21881fd656ebc4345405c520dbc063465b521409933"],["49370a4b5f43412ea25f514e8ecdad05266115e4a7ecb1387231808f8b45963","758f3f41afd6ed428b3081b0512fd62a54c3f3afbb5b6764b653052a12949c9a"],["77f230936ee88cbbd73df930d64702ef881d811e0e1498e2f1c13eb1fc345d74","958ef42a7886b6400a08266e9ba1b37896c95330d97077cbbe8eb3c7671c60d6"],["f2dac991cc4ce4b9ea44887e5c7c0bce58c80074ab9d4dbaeb28531b7739f530","e0dedc9b3b2f8dad4da1f32dec2531df9eb5fbeb0598e4fd1a117dba703a3c37"],["463b3d9f662621fb1b4be8fbbe2520125a216cdfc9dae3debcba4850c690d45b","5ed430d78c296c3543114306dd8622d7c622e27c970a1de31cb377b01af7307e"],["f16f804244e46e2a09232d4aff3b59976b98fac14328a2d1a32496b49998f247","cedabd9b82203f7e13d206fcdf4e33d92a6c53c26e5cce26d6579962c4e31df6"],["caf754272dc84563b0352b7a14311af55d245315ace27c65369e15f7151d41d1","cb474660ef35f5f2a41b643fa5e460575f4fa9b7962232a5c32f908318a04476"],["2600ca4b282cb986f85d0f1709979d8b44a09c07cb86d7c124497bc86f082120","4119b88753c15bd6a693b03fcddbb45d5ac6be74ab5f0ef44b0be9475a7e4b40"],["7635ca72d7e8432c338ec53cd12220bc01c48685e24f7dc8c602a7746998e435","91b649609489d613d1d5e590f78e6d74ecfc061d57048bad9e76f302c5b9c61"],["754e3239f325570cdbbf4a87deee8a66b7f2b33479d468fbc1a50743bf56cc18","673fb86e5bda30fb3cd0ed304ea49a023ee33d0197a695d0c5d98093c536683"],["e3e6bd1071a1e96aff57859c82d570f0330800661d1c952f9fe2694691d9b9e8","59c9e0bba394e76f40c0aa58379a3cb6a5a2283993e90c4167002af4920e37f5"],["186b483d056a033826ae73d88f732985c4ccb1f32ba35f4b4cc47fdcf04aa6eb","3b952d32c67cf77e2e17446e204180ab21fb8090895138b4a4a797f86e80888b"],["df9d70a6b9876ce544c98561f4be4f725442e6d2b737d9c91a8321724ce0963f","55eb2dafd84d6ccd5f862b785dc39d4ab157222720ef9da217b8c45cf2ba2417"],["5edd5cc23c51e87a497ca815d5dce0f8ab52554f849ed8995de64c5f34ce7143","efae9c8dbc14130661e8cec030c89ad0c13c66c0d17a2905cdc706ab7399a868"],["290798c2b6476830da12fe02287e9e777aa3fba1c355b17a722d362f84614fba","e38da76dcd440621988d00bcf79af25d5b29c094db2a23146d003afd41943e7a"],["af3c423a95d9f5b3054754efa150ac39cd29552fe360257362dfdecef4053b45","f98a3fd831eb2b749a93b0e6f35cfb40c8cd5aa667a15581bc2feded498fd9c6"],["766dbb24d134e745cccaa28c99bf274906bb66b26dcf98df8d2fed50d884249a","744b1152eacbe5e38dcc887980da38b897584a65fa06cedd2c924f97cbac5996"],["59dbf46f8c94759ba21277c33784f41645f7b44f6c596a58ce92e666191abe3e","c534ad44175fbc300f4ea6ce648309a042ce739a7919798cd85e216c4a307f6e"],["f13ada95103c4537305e691e74e9a4a8dd647e711a95e73cb62dc6018cfd87b8","e13817b44ee14de663bf4bc808341f326949e21a6a75c2570778419bdaf5733d"],["7754b4fa0e8aced06d4167a2c59cca4cda1869c06ebadfb6488550015a88522c","30e93e864e669d82224b967c3020b8fa8d1e4e350b6cbcc537a48b57841163a2"],["948dcadf5990e048aa3874d46abef9d701858f95de8041d2a6828c99e2262519","e491a42537f6e597d5d28a3224b1bc25df9154efbd2ef1d2cbba2cae5347d57e"],["7962414450c76c1689c7b48f8202ec37fb224cf5ac0bfa1570328a8a3d7c77ab","100b610ec4ffb4760d5c1fc133ef6f6b12507a051f04ac5760afa5b29db83437"],["3514087834964b54b15b160644d915485a16977225b8847bb0dd085137ec47ca","ef0afbb2056205448e1652c48e8127fc6039e77c15c2378b7e7d15a0de293311"],["d3cc30ad6b483e4bc79ce2c9dd8bc54993e947eb8df787b442943d3f7b527eaf","8b378a22d827278d89c5e9be8f9508ae3c2ad46290358630afb34db04eede0a4"],["1624d84780732860ce1c78fcbfefe08b2b29823db913f6493975ba0ff4847610","68651cf9b6da903e0914448c6cd9d4ca896878f5282be4c8cc06e2a404078575"],["733ce80da955a8a26902c95633e62a985192474b5af207da6df7b4fd5fc61cd4","f5435a2bd2badf7d485a4d8b8db9fcce3e1ef8e0201e4578c54673bc1dc5ea1d"],["15d9441254945064cf1a1c33bbd3b49f8966c5092171e699ef258dfab81c045c","d56eb30b69463e7234f5137b73b84177434800bacebfc685fc37bbe9efe4070d"],["a1d0fcf2ec9de675b612136e5ce70d271c21417c9d2b8aaaac138599d0717940","edd77f50bcb5a3cab2e90737309667f2641462a54070f3d519212d39c197a629"],["e22fbe15c0af8ccc5780c0735f84dbe9a790badee8245c06c7ca37331cb36980","a855babad5cd60c88b430a69f53a1a7a38289154964799be43d06d77d31da06"],["311091dd9860e8e20ee13473c1155f5f69635e394704eaa74009452246cfa9b3","66db656f87d1f04fffd1f04788c06830871ec5a64feee685bd80f0b1286d8374"],["34c1fd04d301be89b31c0442d3e6ac24883928b45a9340781867d4232ec2dbdf","9414685e97b1b5954bd46f730174136d57f1ceeb487443dc5321857ba73abee"],["f219ea5d6b54701c1c14de5b557eb42a8d13f3abbcd08affcc2a5e6b049b8d63","4cb95957e83d40b0f73af4544cccf6b1f4b08d3c07b27fb8d8c2962a400766d1"],["d7b8740f74a8fbaab1f683db8f45de26543a5490bca627087236912469a0b448","fa77968128d9c92ee1010f337ad4717eff15db5ed3c049b3411e0315eaa4593b"],["32d31c222f8f6f0ef86f7c98d3a3335ead5bcd32abdd94289fe4d3091aa824bf","5f3032f5892156e39ccd3d7915b9e1da2e6dac9e6f26e961118d14b8462e1661"],["7461f371914ab32671045a155d9831ea8793d77cd59592c4340f86cbc18347b5","8ec0ba238b96bec0cbdddcae0aa442542eee1ff50c986ea6b39847b3cc092ff6"],["ee079adb1df1860074356a25aa38206a6d716b2c3e67453d287698bad7b2b2d6","8dc2412aafe3be5c4c5f37e0ecc5f9f6a446989af04c4e25ebaac479ec1c8c1e"],["16ec93e447ec83f0467b18302ee620f7e65de331874c9dc72bfd8616ba9da6b5","5e4631150e62fb40d0e8c2a7ca5804a39d58186a50e497139626778e25b0674d"],["eaa5f980c245f6f038978290afa70b6bd8855897f98b6aa485b96065d537bd99","f65f5d3e292c2e0819a528391c994624d784869d7e6ea67fb18041024edc07dc"],["78c9407544ac132692ee1910a02439958ae04877151342ea96c4b6b35a49f51","f3e0319169eb9b85d5404795539a5e68fa1fbd583c064d2462b675f194a3ddb4"],["494f4be219a1a77016dcd838431aea0001cdc8ae7a6fc688726578d9702857a5","42242a969283a5f339ba7f075e36ba2af925ce30d767ed6e55f4b031880d562c"],["a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5","204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b"],["c41916365abb2b5d09192f5f2dbeafec208f020f12570a184dbadc3e58595997","4f14351d0087efa49d245b328984989d5caf9450f34bfc0ed16e96b58fa9913"],["841d6063a586fa475a724604da03bc5b92a2e0d2e0a36acfe4c73a5514742881","73867f59c0659e81904f9a1c7543698e62562d6744c169ce7a36de01a8d6154"],["5e95bb399a6971d376026947f89bde2f282b33810928be4ded112ac4d70e20d5","39f23f366809085beebfc71181313775a99c9aed7d8ba38b161384c746012865"],["36e4641a53948fd476c39f8a99fd974e5ec07564b5315d8bf99471bca0ef2f66","d2424b1b1abe4eb8164227b085c9aa9456ea13493fd563e06fd51cf5694c78fc"],["336581ea7bfbbb290c191a2f507a41cf5643842170e914faeab27c2c579f726","ead12168595fe1be99252129b6e56b3391f7ab1410cd1e0ef3dcdcabd2fda224"],["8ab89816dadfd6b6a1f2634fcf00ec8403781025ed6890c4849742706bd43ede","6fdcef09f2f6d0a044e654aef624136f503d459c3e89845858a47a9129cdd24e"],["1e33f1a746c9c5778133344d9299fcaa20b0938e8acff2544bb40284b8c5fb94","60660257dd11b3aa9c8ed618d24edff2306d320f1d03010e33a7d2057f3b3b6"],["85b7c1dcb3cec1b7ee7f30ded79dd20a0ed1f4cc18cbcfcfa410361fd8f08f31","3d98a9cdd026dd43f39048f25a8847f4fcafad1895d7a633c6fed3c35e999511"],["29df9fbd8d9e46509275f4b125d6d45d7fbe9a3b878a7af872a2800661ac5f51","b4c4fe99c775a606e2d8862179139ffda61dc861c019e55cd2876eb2a27d84b"],["a0b1cae06b0a847a3fea6e671aaf8adfdfe58ca2f768105c8082b2e449fce252","ae434102edde0958ec4b19d917a6a28e6b72da1834aff0e650f049503a296cf2"],["4e8ceafb9b3e9a136dc7ff67e840295b499dfb3b2133e4ba113f2e4c0e121e5","cf2174118c8b6d7a4b48f6d534ce5c79422c086a63460502b827ce62a326683c"],["d24a44e047e19b6f5afb81c7ca2f69080a5076689a010919f42725c2b789a33b","6fb8d5591b466f8fc63db50f1c0f1c69013f996887b8244d2cdec417afea8fa3"],["ea01606a7a6c9cdd249fdfcfacb99584001edd28abbab77b5104e98e8e3b35d4","322af4908c7312b0cfbfe369f7a7b3cdb7d4494bc2823700cfd652188a3ea98d"],["af8addbf2b661c8a6c6328655eb96651252007d8c5ea31be4ad196de8ce2131f","6749e67c029b85f52a034eafd096836b2520818680e26ac8f3dfbcdb71749700"],["e3ae1974566ca06cc516d47e0fb165a674a3dabcfca15e722f0e3450f45889","2aeabe7e4531510116217f07bf4d07300de97e4874f81f533420a72eeb0bd6a4"],["591ee355313d99721cf6993ffed1e3e301993ff3ed258802075ea8ced397e246","b0ea558a113c30bea60fc4775460c7901ff0b053d25ca2bdeee98f1a4be5d196"],["11396d55fda54c49f19aa97318d8da61fa8584e47b084945077cf03255b52984","998c74a8cd45ac01289d5833a7beb4744ff536b01b257be4c5767bea93ea57a4"],["3c5d2a1ba39c5a1790000738c9e0c40b8dcdfd5468754b6405540157e017aa7a","b2284279995a34e2f9d4de7396fc18b80f9b8b9fdd270f6661f79ca4c81bd257"],["cc8704b8a60a0defa3a99a7299f2e9c3fbc395afb04ac078425ef8a1793cc030","bdd46039feed17881d1e0862db347f8cf395b74fc4bcdc4e940b74e3ac1f1b13"],["c533e4f7ea8555aacd9777ac5cad29b97dd4defccc53ee7ea204119b2889b197","6f0a256bc5efdf429a2fb6242f1a43a2d9b925bb4a4b3a26bb8e0f45eb596096"],["c14f8f2ccb27d6f109f6d08d03cc96a69ba8c34eec07bbcf566d48e33da6593","c359d6923bb398f7fd4473e16fe1c28475b740dd098075e6c0e8649113dc3a38"],["a6cbc3046bc6a450bac24789fa17115a4c9739ed75f8f21ce441f72e0b90e6ef","21ae7f4680e889bb130619e2c0f95a360ceb573c70603139862afd617fa9b9f"],["347d6d9a02c48927ebfb86c1359b1caf130a3c0267d11ce6344b39f99d43cc38","60ea7f61a353524d1c987f6ecec92f086d565ab687870cb12689ff1e31c74448"],["da6545d2181db8d983f7dcb375ef5866d47c67b1bf31c8cf855ef7437b72656a","49b96715ab6878a79e78f07ce5680c5d6673051b4935bd897fea824b77dc208a"],["c40747cc9d012cb1a13b8148309c6de7ec25d6945d657146b9d5994b8feb1111","5ca560753be2a12fc6de6caf2cb489565db936156b9514e1bb5e83037e0fa2d4"],["4e42c8ec82c99798ccf3a610be870e78338c7f713348bd34c8203ef4037f3502","7571d74ee5e0fb92a7a8b33a07783341a5492144cc54bcc40a94473693606437"],["3775ab7089bc6af823aba2e1af70b236d251cadb0c86743287522a1b3b0dedea","be52d107bcfa09d8bcb9736a828cfa7fac8db17bf7a76a2c42ad961409018cf7"],["cee31cbf7e34ec379d94fb814d3d775ad954595d1314ba8846959e3e82f74e26","8fd64a14c06b589c26b947ae2bcf6bfa0149ef0be14ed4d80f448a01c43b1c6d"],["b4f9eaea09b6917619f6ea6a4eb5464efddb58fd45b1ebefcdc1a01d08b47986","39e5c9925b5a54b07433a4f18c61726f8bb131c012ca542eb24a8ac07200682a"],["d4263dfc3d2df923a0179a48966d30ce84e2515afc3dccc1b77907792ebcc60e","62dfaf07a0f78feb30e30d6295853ce189e127760ad6cf7fae164e122a208d54"],["48457524820fa65a4f8d35eb6930857c0032acc0a4a2de422233eeda897612c4","25a748ab367979d98733c38a1fa1c2e7dc6cc07db2d60a9ae7a76aaa49bd0f77"],["dfeeef1881101f2cb11644f3a2afdfc2045e19919152923f367a1767c11cceda","ecfb7056cf1de042f9420bab396793c0c390bde74b4bbdff16a83ae09a9a7517"],["6d7ef6b17543f8373c573f44e1f389835d89bcbc6062ced36c82df83b8fae859","cd450ec335438986dfefa10c57fea9bcc521a0959b2d80bbf74b190dca712d10"],["e75605d59102a5a2684500d3b991f2e3f3c88b93225547035af25af66e04541f","f5c54754a8f71ee540b9b48728473e314f729ac5308b06938360990e2bfad125"],["eb98660f4c4dfaa06a2be453d5020bc99a0c2e60abe388457dd43fefb1ed620c","6cb9a8876d9cb8520609af3add26cd20a0a7cd8a9411131ce85f44100099223e"],["13e87b027d8514d35939f2e6892b19922154596941888336dc3563e3b8dba942","fef5a3c68059a6dec5d624114bf1e91aac2b9da568d6abeb2570d55646b8adf1"],["ee163026e9fd6fe017c38f06a5be6fc125424b371ce2708e7bf4491691e5764a","1acb250f255dd61c43d94ccc670d0f58f49ae3fa15b96623e5430da0ad6c62b2"],["b268f5ef9ad51e4d78de3a750c2dc89b1e626d43505867999932e5db33af3d80","5f310d4b3c99b9ebb19f77d41c1dee018cf0d34fd4191614003e945a1216e423"],["ff07f3118a9df035e9fad85eb6c7bfe42b02f01ca99ceea3bf7ffdba93c4750d","438136d603e858a3a5c440c38eccbaddc1d2942114e2eddd4740d098ced1f0d8"],["8d8b9855c7c052a34146fd20ffb658bea4b9f69e0d825ebec16e8c3ce2b526a1","cdb559eedc2d79f926baf44fb84ea4d44bcf50fee51d7ceb30e2e7f463036758"],["52db0b5384dfbf05bfa9d472d7ae26dfe4b851ceca91b1eba54263180da32b63","c3b997d050ee5d423ebaf66a6db9f57b3180c902875679de924b69d84a7b375"],["e62f9490d3d51da6395efd24e80919cc7d0f29c3f3fa48c6fff543becbd43352","6d89ad7ba4876b0b22c2ca280c682862f342c8591f1daf5170e07bfd9ccafa7d"],["7f30ea2476b399b4957509c88f77d0191afa2ff5cb7b14fd6d8e7d65aaab1193","ca5ef7d4b231c94c3b15389a5f6311e9daff7bb67b103e9880ef4bff637acaec"],["5098ff1e1d9f14fb46a210fada6c903fef0fb7b4a1dd1d9ac60a0361800b7a00","9731141d81fc8f8084d37c6e7542006b3ee1b40d60dfe5362a5b132fd17ddc0"],["32b78c7de9ee512a72895be6b9cbefa6e2f3c4ccce445c96b9f2c81e2778ad58","ee1849f513df71e32efc3896ee28260c73bb80547ae2275ba497237794c8753c"],["e2cb74fddc8e9fbcd076eef2a7c72b0ce37d50f08269dfc074b581550547a4f7","d3aa2ed71c9dd2247a62df062736eb0baddea9e36122d2be8641abcb005cc4a4"],["8438447566d4d7bedadc299496ab357426009a35f235cb141be0d99cd10ae3a8","c4e1020916980a4da5d01ac5e6ad330734ef0d7906631c4f2390426b2edd791f"],["4162d488b89402039b584c6fc6c308870587d9c46f660b878ab65c82c711d67e","67163e903236289f776f22c25fb8a3afc1732f2b84b4e95dbda47ae5a0852649"],["3fad3fa84caf0f34f0f89bfd2dcf54fc175d767aec3e50684f3ba4a4bf5f683d","cd1bc7cb6cc407bb2f0ca647c718a730cf71872e7d0d2a53fa20efcdfe61826"],["674f2600a3007a00568c1a7ce05d0816c1fb84bf1370798f1c69532faeb1a86b","299d21f9413f33b3edf43b257004580b70db57da0b182259e09eecc69e0d38a5"],["d32f4da54ade74abb81b815ad1fb3b263d82d6c692714bcff87d29bd5ee9f08f","f9429e738b8e53b968e99016c059707782e14f4535359d582fc416910b3eea87"],["30e4e670435385556e593657135845d36fbb6931f72b08cb1ed954f1e3ce3ff6","462f9bce619898638499350113bbc9b10a878d35da70740dc695a559eb88db7b"],["be2062003c51cc3004682904330e4dee7f3dcd10b01e580bf1971b04d4cad297","62188bc49d61e5428573d48a74e1c655b1c61090905682a0d5558ed72dccb9bc"],["93144423ace3451ed29e0fb9ac2af211cb6e84a601df5993c419859fff5df04a","7c10dfb164c3425f5c71a3f9d7992038f1065224f72bb9d1d902a6d13037b47c"],["b015f8044f5fcbdcf21ca26d6c34fb8197829205c7b7d2a7cb66418c157b112c","ab8c1e086d04e813744a655b2df8d5f83b3cdc6faa3088c1d3aea1454e3a1d5f"],["d5e9e1da649d97d89e4868117a465a3a4f8a18de57a140d36b3f2af341a21b52","4cb04437f391ed73111a13cc1d4dd0db1693465c2240480d8955e8592f27447a"],["d3ae41047dd7ca065dbf8ed77b992439983005cd72e16d6f996a5316d36966bb","bd1aeb21ad22ebb22a10f0303417c6d964f8cdd7df0aca614b10dc14d125ac46"],["463e2763d885f958fc66cdd22800f0a487197d0a82e377b49f80af87c897b065","bfefacdb0e5d0fd7df3a311a94de062b26b80c61fbc97508b79992671ef7ca7f"],["7985fdfd127c0567c6f53ec1bb63ec3158e597c40bfe747c83cddfc910641917","603c12daf3d9862ef2b25fe1de289aed24ed291e0ec6708703a5bd567f32ed03"],["74a1ad6b5f76e39db2dd249410eac7f99e74c59cb83d2d0ed5ff1543da7703e9","cc6157ef18c9c63cd6193d83631bbea0093e0968942e8c33d5737fd790e0db08"],["30682a50703375f602d416664ba19b7fc9bab42c72747463a71d0896b22f6da3","553e04f6b018b4fa6c8f39e7f311d3176290d0e0f19ca73f17714d9977a22ff8"],["9e2158f0d7c0d5f26c3791efefa79597654e7a2b2464f52b1ee6c1347769ef57","712fcdd1b9053f09003a3481fa7762e9ffd7c8ef35a38509e2fbf2629008373"],["176e26989a43c9cfeba4029c202538c28172e566e3c4fce7322857f3be327d66","ed8cc9d04b29eb877d270b4878dc43c19aefd31f4eee09ee7b47834c1fa4b1c3"],["75d46efea3771e6e68abb89a13ad747ecf1892393dfc4f1b7004788c50374da8","9852390a99507679fd0b86fd2b39a868d7efc22151346e1a3ca4726586a6bed8"],["809a20c67d64900ffb698c4c825f6d5f2310fb0451c869345b7319f645605721","9e994980d9917e22b76b061927fa04143d096ccc54963e6a5ebfa5f3f8e286c1"],["1b38903a43f7f114ed4500b4eac7083fdefece1cf29c63528d563446f972c180","4036edc931a60ae889353f77fd53de4a2708b26b6f5da72ad3394119daf408f9"]]
}}]})},{"../elliptic":37,"bn.js":35,"hash.js":50}],44:[function(e,t,r){function i(e){return this instanceof i?("string"==typeof e&&(s(a.curves.hasOwnProperty(e),"Unknown curve "+e),e=a.curves[e]),e instanceof a.curves.PresetCurve&&(e={curve:e}),this.curve=e.curve.curve,this.n=this.curve.n,this.nh=this.n.shrn(1),this.g=this.curve.g,this.g=e.curve.g,this.g.precompute(e.curve.n.bitLength()+1),void(this.hash=e.hash||e.curve.hash)):new i(e)}var n=e("bn.js"),a=e("../../elliptic"),o=a.utils,s=o.assert,c=e("./key"),f=e("./signature");t.exports=i,i.prototype.keyPair=function(e,t){return new c(this,e,t)},i.prototype.genKeyPair=function(e){e||(e={});for(var t=new a.hmacDRBG({hash:this.hash,pers:e.pers,entropy:e.entropy||a.rand(this.hash.hmacStrength),nonce:this.n.toArray()}),r=this.n.byteLength(),i=this.n.sub(new n(2));;){var o=new n(t.generate(r));if(!(o.cmp(i)>0))return o.iaddn(1),this.keyPair(o)}},i.prototype._truncateToN=function(e,t){var r=8*e.byteLength()-this.n.bitLength();return r>0&&(e=e.shrn(r)),!t&&e.cmp(this.n)>=0?e.sub(this.n):e},i.prototype.sign=function(e,t,r){t=this.keyPair(t,"hex"),e=this._truncateToN(new n(e,16)),r||(r={});for(var i=this.n.byteLength(),o=t.getPrivate().toArray(),s=o.length;21>s;s++)o.unshift(0);for(var c=e.toArray(),s=c.length;i>s;s++)c.unshift(0);for(var d=new a.hmacDRBG({hash:this.hash,entropy:o,nonce:c}),u=this.n.sub(new n(1));;){var h=new n(d.generate(this.n.byteLength()));if(h=this._truncateToN(h,!0),!(h.cmpn(1)<=0||h.cmp(u)>=0)){var l=this.g.mul(h);if(!l.isInfinity()){var b=l.getX().mod(this.n);if(0!==b.cmpn(0)){var p=h.invm(this.n).mul(b.mul(t.getPrivate()).iadd(e)).mod(this.n);if(0!==p.cmpn(0))return r.canonical&&p.cmp(this.nh)>0&&(p=this.n.sub(p)),new f(b,p)}}}}},i.prototype.verify=function(e,t,r){e=this._truncateToN(new n(e,16)),r=this.keyPair(r,"hex"),t=new f(t,"hex");var i=t.r,a=t.s;if(i.cmpn(1)<0||i.cmp(this.n)>=0)return!1;if(a.cmpn(1)<0||a.cmp(this.n)>=0)return!1;var o=a.invm(this.n),s=o.mul(e).mod(this.n),c=o.mul(i).mod(this.n),d=this.g.mulAdd(s,r.getPublic(),c);return d.isInfinity()?!1:0===d.getX().mod(this.n).cmp(i)}},{"../../elliptic":37,"./key":45,"./signature":46,"bn.js":35}],45:[function(e,t,r){function i(e,t,r){return t instanceof i?t:r instanceof i?r:(t||(t=r,r=null),null!==t&&"object"==typeof t&&(t.x?(r=t,t=null):(t.priv||t.pub)&&(r=t.pub,t=t.priv)),this.ec=e,this.priv=null,this.pub=null,void(this._importPublicHex(t,r)||("hex"===r&&(r=null),t&&this._importPrivate(t),r&&this._importPublic(r))))}{var n=e("bn.js"),a=e("../../elliptic"),o=a.utils;o.assert}t.exports=i,i.prototype.validate=function(){var e=this.getPublic();return e.isInfinity()?{result:!1,reason:"Invalid public key"}:e.validate()?e.mul(this.ec.curve.n).isInfinity()?{result:!0,reason:null}:{result:!1,reason:"Public key * N != O"}:{result:!1,reason:"Public key is not a point"}},i.prototype.getPublic=function(e,t){if(this.pub||(this.pub=this.ec.g.mul(this.priv)),"string"==typeof e&&(t=e,e=null),!t)return this.pub;for(var r=this.ec.curve.p.byteLength(),i=this.pub.getX().toArray(),n=i.length;r>n;n++)i.unshift(0);if(e)var a=[this.pub.getY().isEven()?2:3].concat(i);else{for(var s=this.pub.getY().toArray(),n=s.length;r>n;n++)s.unshift(0);var a=[4].concat(i,s)}return o.encode(a,t)},i.prototype.getPrivate=function(e){return"hex"===e?this.priv.toString(16,2):this.priv},i.prototype._importPrivate=function(e){this.priv=new n(e,16),this.priv=this.priv.mod(this.ec.curve.n)},i.prototype._importPublic=function(e){this.pub=this.ec.curve.point(e.x,e.y)},i.prototype._importPublicHex=function(e,t){e=o.toArray(e,t);var r=this.ec.curve.p.byteLength();if(4===e[0]&&e.length-1===2*r)this.pub=this.ec.curve.point(e.slice(1,1+r),e.slice(1+r,1+2*r));else{if(2!==e[0]&&3!==e[0]||e.length-1!==r)return!1;this.pub=this.ec.curve.pointFromX(3===e[0],e.slice(1,1+r))}return!0},i.prototype.derive=function(e){return e.mul(this.priv).getX()},i.prototype.sign=function(e){return this.ec.sign(e,this)},i.prototype.verify=function(e,t){return this.ec.verify(e,t,this)},i.prototype.inspect=function(){return"<Key priv: "+(this.priv&&this.priv.toString(16,2))+" pub: "+(this.pub&&this.pub.inspect())+" >"}},{"../../elliptic":37,"bn.js":35}],46:[function(e,t,r){function i(e,t){return e instanceof i?e:void(this._importDER(e,t)||(s(e&&t,"Signature without r or s"),this.r=new n(e,16),this.s=new n(t,16)))}var n=e("bn.js"),a=e("../../elliptic"),o=a.utils,s=o.assert;t.exports=i,i.prototype._importDER=function(e,t){if(e=o.toArray(e,t),e.length<6||48!==e[0]||2!==e[2])return!1;var r=e[1];if(1+r>e.length)return!1;var i=e[3];if(i>=128)return!1;if(4+i+2>=e.length)return!1;if(2!==e[4+i])return!1;var a=e[5+i];return a>=128?!1:4+i+2+a>e.length?!1:(this.r=new n(e.slice(4,4+i)),this.s=new n(e.slice(4+i+2,4+i+2+a)),!0)},i.prototype.toDER=function(e){var t=this.r.toArray(),r=this.s.toArray();128&t[0]&&(t=[0].concat(t)),128&r[0]&&(r=[0].concat(r));var i=t.length+r.length+4,n=[48,i,2,t.length];return n=n.concat(t,[2,r.length],r),o.encode(n,e)}},{"../../elliptic":37,"bn.js":35}],47:[function(e,t,r){function i(e){if(!(this instanceof i))return new i(e);this.hash=e.hash,this.predResist=!!e.predResist,this.outLen=this.hash.outSize,this.minEntropy=e.minEntropy||this.hash.hmacStrength,this.reseed=null,this.reseedInterval=null,this.K=null,this.V=null;var t=o.toArray(e.entropy,e.entropyEnc),r=o.toArray(e.nonce,e.nonceEnc),n=o.toArray(e.pers,e.persEnc);s(t.length>=this.minEntropy/8,"Not enough entropy. Minimum is: "+this.minEntropy+" bits"),this._init(t,r,n)}var n=e("hash.js"),a=e("../elliptic"),o=a.utils,s=o.assert;t.exports=i,i.prototype._init=function(e,t,r){var i=e.concat(t).concat(r);this.K=new Array(this.outLen/8),this.V=new Array(this.outLen/8);for(var n=0;n<this.V.length;n++)this.K[n]=0,this.V[n]=1;this._update(i),this.reseed=1,this.reseedInterval=281474976710656},i.prototype._hmac=function(){return new n.hmac(this.hash,this.K)},i.prototype._update=function(e){var t=this._hmac().update(this.V).update([0]);e&&(t=t.update(e)),this.K=t.digest(),this.V=this._hmac().update(this.V).digest(),e&&(this.K=this._hmac().update(this.V).update([1]).update(e).digest(),this.V=this._hmac().update(this.V).digest())},i.prototype.reseed=function(e,t,r,i){"string"!=typeof t&&(i=r,r=t,t=null),e=o.toBuffer(e,t),r=o.toBuffer(r,i),s(e.length>=this.minEntropy/8,"Not enough entropy. Minimum is: "+this.minEntropy+" bits"),this._update(e.concat(r||[])),this.reseed=1},i.prototype.generate=function(e,t,r,i){if(this.reseed>this.reseedInterval)throw new Error("Reseed is required");"string"!=typeof t&&(i=r,r=t,t=null),r&&(r=o.toArray(r,i),this._update(r));for(var n=[];n.length<e;)this.V=this._hmac().update(this.V).digest(),n=n.concat(this.V);var a=n.slice(0,e);return this._update(r),this.reseed++,o.encode(a,t)}},{"../elliptic":37,"hash.js":50}],48:[function(e,t,r){function i(e,t){if(Array.isArray(e))return e.slice();if(!e)return[];var r=[];if("string"==typeof e)if(t){if("hex"===t){e=e.replace(/[^a-z0-9]+/gi,""),e.length%2!==0&&(e="0"+e);for(var i=0;i<e.length;i+=2)r.push(parseInt(e[i]+e[i+1],16))}}else for(var i=0;i<e.length;i++){var n=e.charCodeAt(i),a=n>>8,o=255&n;a?r.push(a,o):r.push(o)}else for(var i=0;i<e.length;i++)r[i]=0|e[i];return r}function n(e){for(var t="",r=0;r<e.length;r++)t+=a(e[r].toString(16));return t}function a(e){return 1===e.length?"0"+e:e}function o(e,t){for(var r=[],i=1<<t+1,n=e.clone();n.cmpn(1)>=0;){var a;if(n.isOdd()){var o=n.andln(i-1);a=o>(i>>1)-1?(i>>1)-o:o,n.isubn(a)}else a=0;r.push(a);for(var s=0!==n.cmpn(0)&&0===n.andln(i-1)?t+1:1,c=1;s>c;c++)r.push(0);n.ishrn(s)}return r}function s(e,t){var r=[[],[]];e=e.clone(),t=t.clone();for(var i=0,n=0;e.cmpn(-i)>0||t.cmpn(-n)>0;){var a=e.andln(3)+i&3,o=t.andln(3)+n&3;3===a&&(a=-1),3===o&&(o=-1);var s;if(0===(1&a))s=0;else{var c=e.andln(7)+i&7;s=3!==c&&5!==c||2!==o?a:-a}r[0].push(s);var f;if(0===(1&o))f=0;else{var c=t.andln(7)+n&7;f=3!==c&&5!==c||2!==a?o:-o}r[1].push(f),2*i===s+1&&(i=1-i),2*n===f+1&&(n=1-n),e.ishrn(1),t.ishrn(1)}return r}var c=(e("bn.js"),r);c.assert=function(e,t){if(!e)throw new Error(t||"Assertion failed")},c.toArray=i,c.toHex=n,c.encode=function(e,t){return"hex"===t?n(e):e},c.zero2=a,c.getNAF=o,c.getJSF=s},{"bn.js":35}],49:[function(e,t,r){function i(e){this.rand=e}var n;if(t.exports=function(e){return n||(n=new i(null)),n.generate(e)},t.exports.Rand=i,i.prototype.generate=function(e){return this._rand(e)},"object"==typeof window)i.prototype._rand=window.crypto&&window.crypto.getRandomValues?function(e){var t=new Uint8Array(e);return window.crypto.getRandomValues(t),t}:window.msCrypto&&window.msCrypto.getRandomValues?function(e){var t=new Uint8Array(e);return window.msCrypto.getRandomValues(t),t}:function(){throw new Error("Not implemented yet")};else try{var a=e("crypto");i.prototype._rand=function(e){return a.randomBytes(e)}}catch(o){i.prototype._rand=function(e){for(var t=new Uint8Array(e),r=0;r<t.length;r++)t[r]=this.rand.getByte();return t}}},{}],50:[function(e,t,r){var i=r;i.utils=e("./hash/utils"),i.common=e("./hash/common"),i.sha=e("./hash/sha"),i.ripemd=e("./hash/ripemd"),i.hmac=e("./hash/hmac"),i.sha1=i.sha.sha1,i.sha256=i.sha.sha256,i.sha224=i.sha.sha224,i.sha384=i.sha.sha384,i.sha512=i.sha.sha512,i.ripemd160=i.ripemd.ripemd160},{"./hash/common":51,"./hash/hmac":52,"./hash/ripemd":53,"./hash/sha":54,"./hash/utils":55}],51:[function(e,t,r){function i(){this.pending=null,this.pendingTotal=0,this.blockSize=this.constructor.blockSize,this.outSize=this.constructor.outSize,this.hmacStrength=this.constructor.hmacStrength,this.padLength=this.constructor.padLength/8,this.endian="big",this._delta8=this.blockSize/8,this._delta32=this.blockSize/32}var n=e("../hash"),a=n.utils,o=a.assert;r.BlockHash=i,i.prototype.update=function(e,t){if(e=a.toArray(e,t),this.pending=this.pending?this.pending.concat(e):e,this.pendingTotal+=e.length,this.pending.length>=this._delta8){e=this.pending;var r=e.length%this._delta8;this.pending=e.slice(e.length-r,e.length),0===this.pending.length&&(this.pending=null),e=a.join32(e,0,e.length-r,this.endian);for(var i=0;i<e.length;i+=this._delta32)this._update(e,i,i+this._delta32)}return this},i.prototype.digest=function(e){return this.update(this._pad()),o(null===this.pending),this._digest(e)},i.prototype._pad=function(){var e=this.pendingTotal,t=this._delta8,r=t-(e+this.padLength)%t,i=new Array(r+this.padLength);i[0]=128;for(var n=1;r>n;n++)i[n]=0;if(e<<=3,"big"===this.endian){for(var a=8;a<this.padLength;a++)i[n++]=0;i[n++]=0,i[n++]=0,i[n++]=0,i[n++]=0,i[n++]=e>>>24&255,i[n++]=e>>>16&255,i[n++]=e>>>8&255,i[n++]=255&e}else{i[n++]=255&e,i[n++]=e>>>8&255,i[n++]=e>>>16&255,i[n++]=e>>>24&255,i[n++]=0,i[n++]=0,i[n++]=0,i[n++]=0;for(var a=8;a<this.padLength;a++)i[n++]=0}return i}},{"../hash":50}],52:[function(e,t,r){function i(e,t,r){return this instanceof i?(this.Hash=e,this.blockSize=e.blockSize/8,this.outSize=e.outSize/8,this.inner=null,this.outer=null,void this._init(a.toArray(t,r))):new i(e,t,r)}var n=e("../hash"),a=n.utils,o=a.assert;t.exports=i,i.prototype._init=function(e){e.length>this.blockSize&&(e=(new this.Hash).update(e).digest()),o(e.length<=this.blockSize);for(var t=e.length;t<this.blockSize;t++)e.push(0);for(var t=0;t<e.length;t++)e[t]^=54;this.inner=(new this.Hash).update(e);for(var t=0;t<e.length;t++)e[t]^=106;this.outer=(new this.Hash).update(e)},i.prototype.update=function(e,t){return this.inner.update(e,t),this},i.prototype.digest=function(e){return this.outer.update(this.inner.digest()),this.outer.digest(e)}},{"../hash":50}],53:[function(e,t,r){function i(){return this instanceof i?(l.call(this),this.h=[1732584193,4023233417,2562383102,271733878,3285377520],void(this.endian="little")):new i}function n(e,t,r,i){return 15>=e?t^r^i:31>=e?t&r|~t&i:47>=e?(t|~r)^i:63>=e?t&i|r&~i:t^(r|~i)}function a(e){return 15>=e?0:31>=e?1518500249:47>=e?1859775393:63>=e?2400959708:2840853838}function o(e){return 15>=e?1352829926:31>=e?1548603684:47>=e?1836072691:63>=e?2053994217:0}var s=e("../hash"),c=s.utils,f=c.rotl32,d=c.sum32,u=c.sum32_3,h=c.sum32_4,l=s.common.BlockHash;c.inherits(i,l),r.ripemd160=i,i.blockSize=512,i.outSize=160,i.hmacStrength=192,i.padLength=64,i.prototype._update=function(e,t){for(var r=this.h[0],i=this.h[1],s=this.h[2],c=this.h[3],l=this.h[4],v=r,y=i,w=s,_=c,S=l,k=0;80>k;k++){var E=d(f(h(r,n(k,i,s,c),e[b[k]+t],a(k)),m[k]),l);r=l,l=c,c=f(s,10),s=i,i=E,E=d(f(h(v,n(79-k,y,w,_),e[p[k]+t],o(k)),g[k]),S),v=S,S=_,_=f(w,10),w=y,y=E}E=u(this.h[1],s,_),this.h[1]=u(this.h[2],c,S),this.h[2]=u(this.h[3],l,v),this.h[3]=u(this.h[4],r,y),this.h[4]=u(this.h[0],i,w),this.h[0]=E},i.prototype._digest=function(e){return"hex"===e?c.toHex32(this.h,"little"):c.split32(this.h,"little")};var b=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13],p=[5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11],m=[11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6],g=[8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]},{"../hash":50}],54:[function(e,t,r){function i(){return this instanceof i?(Y.call(this),this.h=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225],this.k=X,void(this.W=new Array(64))):new i}function n(){return this instanceof n?(i.call(this),void(this.h=[3238371032,914150663,812702999,4144912697,4290775857,1750603025,1694076839,3204075428])):new n}function a(){return this instanceof a?(Y.call(this),this.h=[1779033703,4089235720,3144134277,2227873595,1013904242,4271175723,2773480762,1595750129,1359893119,2917565137,2600822924,725511199,528734635,4215389547,1541459225,327033209],this.k=J,void(this.W=new Array(160))):new a}function o(){return this instanceof o?(a.call(this),void(this.h=[3418070365,3238371032,1654270250,914150663,2438529370,812702999,355462360,4144912697,1731405415,4290775857,2394180231,1750603025,3675008525,1694076839,1203062813,3204075428])):new o}function s(){return this instanceof s?(Y.call(this),this.h=[1732584193,4023233417,2562383102,271733878,3285377520],void(this.W=new Array(80))):new s}function c(e,t,r){return e&t^~e&r}function f(e,t,r){return e&t^e&r^t&r}function d(e,t,r){return e^t^r}function u(e){return M(e,2)^M(e,13)^M(e,22)}function h(e){return M(e,6)^M(e,11)^M(e,25)}function l(e){return M(e,7)^M(e,18)^e>>>3}function b(e){return M(e,17)^M(e,19)^e>>>10}function p(e,t,r,i){return 0===e?c(t,r,i):1===e||3===e?d(t,r,i):2===e?f(t,r,i):void 0}function m(e,t,r,i,n,a){var o=e&r^~e&n;return 0>o&&(o+=4294967296),o}function g(e,t,r,i,n,a){var o=t&i^~t&a;return 0>o&&(o+=4294967296),o}function v(e,t,r,i,n,a){var o=e&r^e&n^r&n;return 0>o&&(o+=4294967296),o}function y(e,t,r,i,n,a){var o=t&i^t&a^i&a;return 0>o&&(o+=4294967296),o}function w(e,t){var r=q(e,t,28),i=q(t,e,2),n=q(t,e,7),a=r^i^n;return 0>a&&(a+=4294967296),a}function _(e,t){var r=L(e,t,28),i=L(t,e,2),n=L(t,e,7),a=r^i^n;return 0>a&&(a+=4294967296),a}function S(e,t){var r=q(e,t,14),i=q(e,t,18),n=q(t,e,9),a=r^i^n;return 0>a&&(a+=4294967296),a}function k(e,t){var r=L(e,t,14),i=L(e,t,18),n=L(t,e,9),a=r^i^n;return 0>a&&(a+=4294967296),a}function E(e,t){var r=q(e,t,1),i=q(e,t,8),n=D(e,t,7),a=r^i^n;return 0>a&&(a+=4294967296),a}function x(e,t){var r=L(e,t,1),i=L(e,t,8),n=U(e,t,7),a=r^i^n;return 0>a&&(a+=4294967296),a}function j(e,t){var r=q(e,t,19),i=q(t,e,29),n=D(e,t,6),a=r^i^n;return 0>a&&(a+=4294967296),a}function A(e,t){var r=L(e,t,19),i=L(t,e,29),n=U(e,t,6),a=r^i^n;return 0>a&&(a+=4294967296),a}var I=e("../hash"),B=I.utils,z=B.assert,M=B.rotr32,R=B.rotl32,P=B.sum32,T=B.sum32_4,C=B.sum32_5,q=B.rotr64_hi,L=B.rotr64_lo,D=B.shr64_hi,U=B.shr64_lo,O=B.sum64,N=B.sum64_hi,K=B.sum64_lo,H=B.sum64_4_hi,F=B.sum64_4_lo,W=B.sum64_5_hi,V=B.sum64_5_lo,Y=I.common.BlockHash,X=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298],J=[1116352408,3609767458,1899447441,602891725,3049323471,3964484399,3921009573,2173295548,961987163,4081628472,1508970993,3053834265,2453635748,2937671579,2870763221,3664609560,3624381080,2734883394,310598401,1164996542,607225278,1323610764,1426881987,3590304994,1925078388,4068182383,2162078206,991336113,2614888103,633803317,3248222580,3479774868,3835390401,2666613458,4022224774,944711139,264347078,2341262773,604807628,2007800933,770255983,1495990901,1249150122,1856431235,1555081692,3175218132,1996064986,2198950837,2554220882,3999719339,2821834349,766784016,2952996808,2566594879,3210313671,3203337956,3336571891,1034457026,3584528711,2466948901,113926993,3758326383,338241895,168717936,666307205,1188179964,773529912,1546045734,1294757372,1522805485,1396182291,2643833823,1695183700,2343527390,1986661051,1014477480,2177026350,1206759142,2456956037,344077627,2730485921,1290863460,2820302411,3158454273,3259730800,3505952657,3345764771,106217008,3516065817,3606008344,3600352804,1432725776,4094571909,1467031594,275423344,851169720,430227734,3100823752,506948616,1363258195,659060556,3750685593,883997877,3785050280,958139571,3318307427,1322822218,3812723403,1537002063,2003034995,1747873779,3602036899,1955562222,1575990012,2024104815,1125592928,2227730452,2716904306,2361852424,442776044,2428436474,593698344,2756734187,3733110249,3204031479,2999351573,3329325298,3815920427,3391569614,3928383900,3515267271,566280711,3940187606,3454069534,4118630271,4000239992,116418474,1914138554,174292421,2731055270,289380356,3203993006,460393269,320620315,685471733,587496836,852142971,1086792851,1017036298,365543100,1126000580,2618297676,1288033470,3409855158,1501505948,4234509866,1607167915,987167468,1816402316,1246189591],G=[1518500249,1859775393,2400959708,3395469782];B.inherits(i,Y),r.sha256=i,i.blockSize=512,i.outSize=256,i.hmacStrength=192,i.padLength=64,i.prototype._update=function(e,t){for(var r=this.W,i=0;16>i;i++)r[i]=e[t+i];for(;i<r.length;i++)r[i]=T(b(r[i-2]),r[i-7],l(r[i-15]),r[i-16]);var n=this.h[0],a=this.h[1],o=this.h[2],s=this.h[3],d=this.h[4],p=this.h[5],m=this.h[6],g=this.h[7];z(this.k.length===r.length);for(var i=0;i<r.length;i++){var v=C(g,h(d),c(d,p,m),this.k[i],r[i]),y=P(u(n),f(n,a,o));g=m,m=p,p=d,d=P(s,v),s=o,o=a,a=n,n=P(v,y)}this.h[0]=P(this.h[0],n),this.h[1]=P(this.h[1],a),this.h[2]=P(this.h[2],o),this.h[3]=P(this.h[3],s),this.h[4]=P(this.h[4],d),this.h[5]=P(this.h[5],p),this.h[6]=P(this.h[6],m),this.h[7]=P(this.h[7],g)},i.prototype._digest=function(e){return"hex"===e?B.toHex32(this.h,"big"):B.split32(this.h,"big")},B.inherits(n,i),r.sha224=n,n.blockSize=512,n.outSize=224,n.hmacStrength=192,n.padLength=64,n.prototype._digest=function(e){return"hex"===e?B.toHex32(this.h.slice(0,7),"big"):B.split32(this.h.slice(0,7),"big")},B.inherits(a,Y),r.sha512=a,a.blockSize=1024,a.outSize=512,a.hmacStrength=192,a.padLength=128,a.prototype._prepareBlock=function(e,t){for(var r=this.W,i=0;32>i;i++)r[i]=e[t+i];for(;i<r.length;i+=2){var n=j(r[i-4],r[i-3]),a=A(r[i-4],r[i-3]),o=r[i-14],s=r[i-13],c=E(r[i-30],r[i-29]),f=x(r[i-30],r[i-29]),d=r[i-32],u=r[i-31];r[i]=H(n,a,o,s,c,f,d,u),r[i+1]=F(n,a,o,s,c,f,d,u)}},a.prototype._update=function(e,t){this._prepareBlock(e,t);var r=this.W,i=this.h[0],n=this.h[1],a=this.h[2],o=this.h[3],s=this.h[4],c=this.h[5],f=this.h[6],d=this.h[7],u=this.h[8],h=this.h[9],l=this.h[10],b=this.h[11],p=this.h[12],E=this.h[13],x=this.h[14],j=this.h[15];z(this.k.length===r.length);for(var A=0;A<r.length;A+=2){var I=x,B=j,M=S(u,h),R=k(u,h),P=m(u,h,l,b,p,E),T=g(u,h,l,b,p,E),C=this.k[A],q=this.k[A+1],L=r[A],D=r[A+1],U=W(I,B,M,R,P,T,C,q,L,D),H=V(I,B,M,R,P,T,C,q,L,D),I=w(i,n),B=_(i,n),M=v(i,n,a,o,s,c),R=y(i,n,a,o,s,c),F=N(I,B,M,R),Y=K(I,B,M,R);x=p,j=E,p=l,E=b,l=u,b=h,u=N(f,d,U,H),h=K(d,d,U,H),f=s,d=c,s=a,c=o,a=i,o=n,i=N(U,H,F,Y),n=K(U,H,F,Y)}O(this.h,0,i,n),O(this.h,2,a,o),O(this.h,4,s,c),O(this.h,6,f,d),O(this.h,8,u,h),O(this.h,10,l,b),O(this.h,12,p,E),O(this.h,14,x,j)},a.prototype._digest=function(e){return"hex"===e?B.toHex32(this.h,"big"):B.split32(this.h,"big")},B.inherits(o,a),r.sha384=o,o.blockSize=1024,o.outSize=384,o.hmacStrength=192,o.padLength=128,o.prototype._digest=function(e){return"hex"===e?B.toHex32(this.h.slice(0,12),"big"):B.split32(this.h.slice(0,12),"big")},B.inherits(s,Y),r.sha1=s,s.blockSize=512,s.outSize=160,s.hmacStrength=80,s.padLength=64,s.prototype._update=function(e,t){for(var r=this.W,i=0;16>i;i++)r[i]=e[t+i];for(;i<r.length;i++)r[i]=R(r[i-3]^r[i-8]^r[i-14]^r[i-16],1);for(var n=this.h[0],a=this.h[1],o=this.h[2],s=this.h[3],c=this.h[4],i=0;i<r.length;i++){var f=~~(i/20),d=C(R(n,5),p(f,a,o,s),c,r[i],G[f]);c=s,s=o,o=R(a,30),a=n,n=d}this.h[0]=P(this.h[0],n),this.h[1]=P(this.h[1],a),this.h[2]=P(this.h[2],o),this.h[3]=P(this.h[3],s),this.h[4]=P(this.h[4],c)},s.prototype._digest=function(e){return"hex"===e?B.toHex32(this.h,"big"):B.split32(this.h,"big")}},{"../hash":50}],55:[function(e,t,r){function i(e,t){if(Array.isArray(e))return e.slice();if(!e)return[];var r=[];if("string"==typeof e)if(t){if("hex"===t){e=e.replace(/[^a-z0-9]+/gi,""),e.length%2!==0&&(e="0"+e);for(var i=0;i<e.length;i+=2)r.push(parseInt(e[i]+e[i+1],16))}}else for(var i=0;i<e.length;i++){var n=e.charCodeAt(i),a=n>>8,o=255&n;a?r.push(a,o):r.push(o)}else for(var i=0;i<e.length;i++)r[i]=0|e[i];return r}function n(e){for(var t="",r=0;r<e.length;r++)t+=s(e[r].toString(16));return t}function a(e){var t=e>>>24|e>>>8&65280|e<<8&16711680|(255&e)<<24;return t>>>0}function o(e,t){for(var r="",i=0;i<e.length;i++){var n=e[i];"little"===t&&(n=a(n)),r+=c(n.toString(16))}return r}function s(e){return 1===e.length?"0"+e:e}function c(e){return 7===e.length?"0"+e:6===e.length?"00"+e:5===e.length?"000"+e:4===e.length?"0000"+e:3===e.length?"00000"+e:2===e.length?"000000"+e:1===e.length?"0000000"+e:e}function f(e,t,r,i){var n=r-t;g(n%4===0);for(var a=new Array(n/4),o=0,s=t;o<a.length;o++,s+=4){var c;c="big"===i?e[s]<<24|e[s+1]<<16|e[s+2]<<8|e[s+3]:e[s+3]<<24|e[s+2]<<16|e[s+1]<<8|e[s],a[o]=c>>>0}return a}function d(e,t){for(var r=new Array(4*e.length),i=0,n=0;i<e.length;i++,n+=4){var a=e[i];"big"===t?(r[n]=a>>>24,r[n+1]=a>>>16&255,r[n+2]=a>>>8&255,r[n+3]=255&a):(r[n+3]=a>>>24,r[n+2]=a>>>16&255,r[n+1]=a>>>8&255,r[n]=255&a)}return r}function u(e,t){return e>>>t|e<<32-t}function h(e,t){return e<<t|e>>>32-t}function l(e,t){return e+t>>>0}function b(e,t,r){return e+t+r>>>0}function p(e,t,r,i){return e+t+r+i>>>0}function m(e,t,r,i,n){return e+t+r+i+n>>>0}function g(e,t){if(!e)throw new Error(t||"Assertion failed")}function v(e,t,r,i){var n=e[t],a=e[t+1],o=i+a>>>0,s=(i>o?1:0)+r+n;e[t]=s>>>0,e[t+1]=o}function y(e,t,r,i){var n=t+i>>>0,a=(t>n?1:0)+e+r;return a>>>0}function w(e,t,r,i){var n=t+i;return n>>>0}function _(e,t,r,i,n,a,o,s){var c=0,f=t;f=f+i>>>0,c+=t>f?1:0,f=f+a>>>0,c+=a>f?1:0,f=f+s>>>0,c+=s>f?1:0;var d=e+r+n+o+c;return d>>>0}function S(e,t,r,i,n,a,o,s){var c=t+i+a+s;return c>>>0}function k(e,t,r,i,n,a,o,s,c,f){var d=0,u=t;u=u+i>>>0,d+=t>u?1:0,u=u+a>>>0,d+=a>u?1:0,u=u+s>>>0,d+=s>u?1:0,u=u+f>>>0,d+=f>u?1:0;var h=e+r+n+o+c+d;return h>>>0}function E(e,t,r,i,n,a,o,s,c,f){var d=t+i+a+s+f;return d>>>0}function x(e,t,r){var i=t<<32-r|e>>>r;return i>>>0}function j(e,t,r){var i=e<<32-r|t>>>r;return i>>>0}function A(e,t,r){return e>>>r}function I(e,t,r){var i=e<<32-r|t>>>r;return i>>>0}var B=r,z=e("inherits");B.toArray=i,B.toHex=n,B.htonl=a,B.toHex32=o,B.zero2=s,B.zero8=c,B.join32=f,B.split32=d,B.rotr32=u,B.rotl32=h,B.sum32=l,B.sum32_3=b,B.sum32_4=p,B.sum32_5=m,B.assert=g,B.inherits=z,r.sum64=v,r.sum64_hi=y,r.sum64_lo=w,r.sum64_4_hi=_,r.sum64_4_lo=S,r.sum64_5_hi=k,r.sum64_5_lo=E,r.rotr64_hi=x,r.rotr64_lo=j,r.shr64_hi=A,r.shr64_lo=I},{inherits:151}],56:[function(e,t,r){t.exports={name:"elliptic",version:"1.0.1",description:"EC cryptography",main:"lib/elliptic.js",scripts:{test:"mocha --reporter=spec test/*-test.js"},repository:{type:"git",url:"git@github.com:indutny/elliptic"},keywords:["EC","Elliptic","curve","Cryptography"],author:{name:"Fedor Indutny",email:"fedor@indutny.com"},license:"MIT",bugs:{url:"https://github.com/indutny/elliptic/issues"},homepage:"https://github.com/indutny/elliptic",devDependencies:{browserify:"^3.44.2",mocha:"^1.18.2","uglify-js":"^2.4.13"},dependencies:{"bn.js":"^1.0.0",brorand:"^1.0.1","hash.js":"^1.0.0",inherits:"^2.0.1"},gitHead:"17dc013761dd1efcfb868e2b06b0b897627b40be",_id:"elliptic@1.0.1",_shasum:"d180376b66a17d74995c837796362ac4d22aefe3",_from:"elliptic@^1.0.0",_npmVersion:"1.4.28",_npmUser:{name:"indutny",email:"fedor@indutny.com"},maintainers:[{name:"indutny",email:"fedor@indutny.com"}],dist:{shasum:"d180376b66a17d74995c837796362ac4d22aefe3",tarball:"http://registry.npmjs.org/elliptic/-/elliptic-1.0.1.tgz"},directories:{},_resolved:"https://registry.npmjs.org/elliptic/-/elliptic-1.0.1.tgz",readme:"ERROR: No README data found!"}},{}],57:[function(e,t,r){(function(r){var i=e("create-hash");t.exports=function(e,t,n){n/=8;for(var a,o,s,c=0,f=new r(n),d=0;;){if(a=i("md5"),d++>0&&a.update(o),a.update(e),a.update(t),o=a.digest(),s=0,n>0)for(;;){if(0===n)break;if(s===o.length)break;f[c++]=o[s++],n--}if(0===n)break}for(s=0;s<o.length;s++)o[s]=0;return f}}).call(this,e("buffer").Buffer)},{buffer:9,"create-hash":101}],58:[function(e,t,r){t.exports={"2.16.840.1.101.3.4.1.1":"aes-128-ecb","2.16.840.1.101.3.4.1.2":"aes-128-cbc","2.16.840.1.101.3.4.1.3":"aes-128-ofb","2.16.840.1.101.3.4.1.4":"aes-128-cfb","2.16.840.1.101.3.4.1.21":"aes-192-ecb","2.16.840.1.101.3.4.1.22":"aes-192-cbc","2.16.840.1.101.3.4.1.23":"aes-192-ofb","2.16.840.1.101.3.4.1.24":"aes-192-cfb","2.16.840.1.101.3.4.1.41":"aes-256-ecb","2.16.840.1.101.3.4.1.42":"aes-256-cbc","2.16.840.1.101.3.4.1.43":"aes-256-ofb","2.16.840.1.101.3.4.1.44":"aes-256-cfb"}},{}],59:[function(e,t,r){var i=e("asn1.js"),n=i.define("RSAPrivateKey",function(){this.seq().obj(this.key("version")["int"](),this.key("modulus")["int"](),this.key("publicExponent")["int"](),this.key("privateExponent")["int"](),this.key("prime1")["int"](),this.key("prime2")["int"](),this.key("exponent1")["int"](),this.key("exponent2")["int"](),this.key("coefficient")["int"]())});r.RSAPrivateKey=n;var a=i.define("RSAPublicKey",function(){this.seq().obj(this.key("modulus")["int"](),this.key("publicExponent")["int"]())});r.RSAPublicKey=a;var o=i.define("SubjectPublicKeyInfo",function(){this.seq().obj(this.key("algorithm").use(s),this.key("subjectPublicKey").bitstr())});r.PublicKey=o;var s=i.define("AlgorithmIdentifier",function(){this.seq().obj(this.key("algorithm").objid(),this.key("none").null_().optional(),this.key("curve").objid().optional(),this.key("params").seq().obj(this.key("p")["int"](),this.key("q")["int"](),this.key("g")["int"]()).optional())}),c=i.define("PrivateKeyInfo",function(){this.seq().obj(this.key("version")["int"](),this.key("algorithm").use(s),this.key("subjectPrivateKey").octstr())});r.PrivateKey=c;var f=i.define("EncryptedPrivateKeyInfo",function(){this.seq().obj(this.key("algorithm").seq().obj(this.key("id").objid(),this.key("decrypt").seq().obj(this.key("kde").seq().obj(this.key("id").objid(),this.key("kdeparams").seq().obj(this.key("salt").octstr(),this.key("iters")["int"]())),this.key("cipher").seq().obj(this.key("algo").objid(),this.key("iv").octstr()))),this.key("subjectPrivateKey").octstr())});r.EncryptedPrivateKey=f;var d=i.define("DSAPrivateKey",function(){this.seq().obj(this.key("version")["int"](),this.key("p")["int"](),this.key("q")["int"](),this.key("g")["int"](),this.key("pub_key")["int"](),this.key("priv_key")["int"]())});r.DSAPrivateKey=d,r.DSAparam=i.define("DSAparam",function(){this["int"]()});var u=i.define("ECPrivateKey",function(){this.seq().obj(this.key("version")["int"](),this.key("privateKey").octstr(),this.key("parameters").optional().explicit(0).use(h),this.key("publicKey").optional().explicit(1).bitstr())});r.ECPrivateKey=u;var h=i.define("ECParameters",function(){this.choice({namedCurve:this.objid()})});r.signature=i.define("signature",function(){this.seq().obj(this.key("r")["int"](),this.key("s")["int"]())})},{"asn1.js":62}],60:[function(e,t,r){(function(r){var i=/Proc-Type: 4,ENCRYPTED\n\r?DEK-Info: AES-((?:128)|(?:192)|(?:256))-CBC,([0-9A-H]+)\n\r?\n\r?([0-9A-z\n\r\+\/\=]+)\n\r?/m,n=/^-----BEGIN (.*) KEY-----\n/m,a=/^-----BEGIN (.*) KEY-----\n\r?([0-9A-z\n\r\+\/\=]+)\n\r?-----END \1 KEY-----$/m,o=e("./EVP_BytesToKey"),s=e("browserify-aes");t.exports=function(e,t){var c,f=e.toString(),d=f.match(i);if(d){var u="aes"+d[1],h=new r(d[2],"hex"),l=new r(d[3].replace(/\n\r?/g,""),"base64"),b=o(t,h.slice(0,8),parseInt(d[1])),p=[],m=s.createDecipheriv(u,b,h);p.push(m.update(l)),p.push(m["final"]()),c=r.concat(p)}else{var g=f.match(a);c=new r(g[2].replace(/\n\r?/g,""),"base64")}var v=f.match(n)[1]+" KEY";return{tag:v,data:c}}}).call(this,e("buffer").Buffer)},{"./EVP_BytesToKey":57,"browserify-aes":17,buffer:9}],61:[function(e,t,r){(function(r){function i(e){var t;"object"!=typeof e||r.isBuffer(e)||(t=e.passphrase,e=e.key),"string"==typeof e&&(e=new r(e));var i,o,c=s(e,t),f=c.tag,d=c.data;switch(f){case"PUBLIC KEY":switch(o=a.PublicKey.decode(d,"der"),i=o.algorithm.algorithm.join(".")){case"1.2.840.113549.1.1.1":return a.RSAPublicKey.decode(o.subjectPublicKey.data,"der");case"1.2.840.10045.2.1":return o.subjectPrivateKey=o.subjectPublicKey,{type:"ec",data:o};case"1.2.840.10040.4.1":return o.algorithm.params.pub_key=a.DSAparam.decode(o.subjectPublicKey.data,"der"),{type:"dsa",data:o.algorithm.params};default:throw new Error("unknown key id "+i)}throw new Error("unknown key type "+f);case"ENCRYPTED PRIVATE KEY":d=a.EncryptedPrivateKey.decode(d,"der"),d=n(d,t);case"PRIVATE KEY":switch(o=a.PrivateKey.decode(d,"der"),i=o.algorithm.algorithm.join(".")){case"1.2.840.113549.1.1.1":return a.RSAPrivateKey.decode(o.subjectPrivateKey,"der");case"1.2.840.10045.2.1":return{curve:o.algorithm.curve,privateKey:a.ECPrivateKey.decode(o.subjectPrivateKey,"der").privateKey};case"1.2.840.10040.4.1":return o.algorithm.params.priv_key=a.DSAparam.decode(o.subjectPrivateKey,"der"),{type:"dsa",params:o.algorithm.params};default:throw new Error("unknown key id "+i)}throw new Error("unknown key type "+f);case"RSA PUBLIC KEY":return a.RSAPublicKey.decode(d,"der");case"RSA PRIVATE KEY":return a.RSAPrivateKey.decode(d,"der");case"DSA PRIVATE KEY":return{type:"dsa",params:a.DSAPrivateKey.decode(d,"der")};case"EC PRIVATE KEY":return d=a.ECPrivateKey.decode(d,"der"),{curve:d.parameters.value,privateKey:d.privateKey};default:throw new Error("unknown key type "+f)}}function n(e,t){var i=e.algorithm.decrypt.kde.kdeparams.salt,n=e.algorithm.decrypt.kde.kdeparams.iters,a=o[e.algorithm.decrypt.cipher.algo.join(".")],s=e.algorithm.decrypt.cipher.iv,d=e.subjectPrivateKey,u=parseInt(a.split("-")[1],10)/8,h=f.pbkdf2Sync(t,i,n,u),l=c.createDecipheriv(a,h,s),b=[];return b.push(l.update(d)),b.push(l["final"]()),r.concat(b)}var a=e("./asn1"),o=e("./aesid.json"),s=e("./fixProc"),c=e("browserify-aes"),f=e("pbkdf2-compat");t.exports=i,i.signature=a.signature}).call(this,e("buffer").Buffer)},{"./aesid.json":58,"./asn1":59,"./fixProc":60,"browserify-aes":17,buffer:9,"pbkdf2-compat":75}],62:[function(e,t,r){var i=r;i.bignum=e("bn.js"),i.define=e("./asn1/api").define,i.base=e("./asn1/base"),i.constants=e("./asn1/constants"),
i.decoders=e("./asn1/decoders"),i.encoders=e("./asn1/encoders")},{"./asn1/api":63,"./asn1/base":65,"./asn1/constants":69,"./asn1/decoders":71,"./asn1/encoders":73,"bn.js":35}],63:[function(e,t,r){function i(e,t){this.name=e,this.body=t,this.decoders={},this.encoders={}}var n=e("../asn1"),a=e("inherits"),o=r;o.define=function(e,t){return new i(e,t)},i.prototype._createNamed=function(t){var r;try{r=e("vm").runInThisContext("(function "+this.name+"(entity) {\n  this._initNamed(entity);\n})")}catch(i){r=function(e){this._initNamed(e)}}return a(r,t),r.prototype._initNamed=function(e){t.call(this,e)},new r(this)},i.prototype._getDecoder=function(e){return this.decoders.hasOwnProperty(e)||(this.decoders[e]=this._createNamed(n.decoders[e])),this.decoders[e]},i.prototype.decode=function(e,t,r){return this._getDecoder(t).decode(e,r)},i.prototype._getEncoder=function(e){return this.encoders.hasOwnProperty(e)||(this.encoders[e]=this._createNamed(n.encoders[e])),this.encoders[e]},i.prototype.encode=function(e,t,r){return this._getEncoder(t).encode(e,r)}},{"../asn1":62,inherits:151,vm:167}],64:[function(e,t,r){function i(e,t){return o.call(this,t),s.isBuffer(e)?(this.base=e,this.offset=0,void(this.length=e.length)):void this.error("Input not Buffer")}function n(e,t){if(Array.isArray(e))this.length=0,this.value=e.map(function(e){return e instanceof n||(e=new n(e,t)),this.length+=e.length,e},this);else if("number"==typeof e){if(!(e>=0&&255>=e))return t.error("non-byte EncoderBuffer value");this.value=e,this.length=1}else if("string"==typeof e)this.value=e,this.length=s.byteLength(e);else{if(!s.isBuffer(e))return t.error("Unsupported type: "+typeof e);this.value=e,this.length=e.length}}var a=e("inherits"),o=e("../base").Reporter,s=e("buffer").Buffer;a(i,o),r.DecoderBuffer=i,i.prototype.save=function(){return{offset:this.offset}},i.prototype.restore=function(e){var t=new i(this.base);return t.offset=e.offset,t.length=this.offset,this.offset=e.offset,t},i.prototype.isEmpty=function(){return this.offset===this.length},i.prototype.readUInt8=function(e){return this.offset+1<=this.length?this.base.readUInt8(this.offset++,!0):this.error(e||"DecoderBuffer overrun")},i.prototype.skip=function(e,t){if(!(this.offset+e<=this.length))return this.error(t||"DecoderBuffer overrun");var r=new i(this.base);return r._reporterState=this._reporterState,r.offset=this.offset,r.length=this.offset+e,this.offset+=e,r},i.prototype.raw=function(e){return this.base.slice(e?e.offset:this.offset,this.length)},r.EncoderBuffer=n,n.prototype.join=function(e,t){return e||(e=new s(this.length)),t||(t=0),0===this.length?e:(Array.isArray(this.value)?this.value.forEach(function(r){r.join(e,t),t+=r.length}):("number"==typeof this.value?e[t]=this.value:"string"==typeof this.value?e.write(this.value,t):s.isBuffer(this.value)&&this.value.copy(e,t),t+=this.length),e)}},{"../base":65,buffer:9,inherits:151}],65:[function(e,t,r){var i=r;i.Reporter=e("./reporter").Reporter,i.DecoderBuffer=e("./buffer").DecoderBuffer,i.EncoderBuffer=e("./buffer").EncoderBuffer,i.Node=e("./node")},{"./buffer":64,"./node":66,"./reporter":67}],66:[function(e,t,r){function i(e,t){var r={};this._baseState=r,r.enc=e,r.parent=t||null,r.children=null,r.tag=null,r.args=null,r.reverseArgs=null,r.choice=null,r.optional=!1,r.any=!1,r.obj=!1,r.use=null,r.useDecoder=null,r.key=null,r["default"]=null,r.explicit=null,r.implicit=null,r.parent||(r.children=[],this._wrap())}var n=e("../base").Reporter,a=e("../base").EncoderBuffer,o=e("minimalistic-assert"),s=["seq","seqof","set","setof","octstr","bitstr","objid","bool","gentime","utctime","null_","enum","int","ia5str"],c=["key","obj","use","optional","explicit","implicit","def","choice","any"].concat(s),f=["_peekTag","_decodeTag","_use","_decodeStr","_decodeObjid","_decodeTime","_decodeNull","_decodeInt","_decodeBool","_decodeList","_encodeComposite","_encodeStr","_encodeObjid","_encodeTime","_encodeNull","_encodeInt","_encodeBool"];t.exports=i;var d=["enc","parent","children","tag","args","reverseArgs","choice","optional","any","obj","use","alteredUse","key","default","explicit","implicit"];i.prototype.clone=function(){var e=this._baseState,t={};d.forEach(function(r){t[r]=e[r]});var r=new this.constructor(t.parent);return r._baseState=t,r},i.prototype._wrap=function(){var e=this._baseState;c.forEach(function(t){this[t]=function(){var r=new this.constructor(this);return e.children.push(r),r[t].apply(r,arguments)}},this)},i.prototype._init=function(e){var t=this._baseState;o(null===t.parent),e.call(this),t.children=t.children.filter(function(e){return e._baseState.parent===this},this),o.equal(t.children.length,1,"Root node can have only one child")},i.prototype._useArgs=function(e){var t=this._baseState,r=e.filter(function(e){return e instanceof this.constructor},this);e=e.filter(function(e){return!(e instanceof this.constructor)},this),0!==r.length&&(o(null===t.children),t.children=r,r.forEach(function(e){e._baseState.parent=this},this)),0!==e.length&&(o(null===t.args),t.args=e,t.reverseArgs=e.map(function(e){if("object"!=typeof e||e.constructor!==Object)return e;var t={};return Object.keys(e).forEach(function(r){r==(0|r)&&(r|=0);var i=e[r];t[i]=r}),t}))},f.forEach(function(e){i.prototype[e]=function(){var t=this._baseState;throw new Error(e+" not implemented for encoding: "+t.enc)}}),s.forEach(function(e){i.prototype[e]=function(){var t=this._baseState,r=Array.prototype.slice.call(arguments);return o(null===t.tag),t.tag=e,this._useArgs(r),this}}),i.prototype.use=function(e){var t=this._baseState;return o(null===t.use),t.use=e,this},i.prototype.optional=function(){var e=this._baseState;return e.optional=!0,this},i.prototype.def=function(e){var t=this._baseState;return o(null===t["default"]),t["default"]=e,t.optional=!0,this},i.prototype.explicit=function(e){var t=this._baseState;return o(null===t.explicit&&null===t.implicit),t.explicit=e,this},i.prototype.implicit=function(e){var t=this._baseState;return o(null===t.explicit&&null===t.implicit),t.implicit=e,this},i.prototype.obj=function(){var e=this._baseState,t=Array.prototype.slice.call(arguments);return e.obj=!0,0!==t.length&&this._useArgs(t),this},i.prototype.key=function(e){var t=this._baseState;return o(null===t.key),t.key=e,this},i.prototype.any=function(){var e=this._baseState;return e.any=!0,this},i.prototype.choice=function(e){var t=this._baseState;return o(null===t.choice),t.choice=e,this._useArgs(Object.keys(e).map(function(t){return e[t]})),this},i.prototype._decode=function(e){var t=this._baseState;if(null===t.parent)return e.wrapResult(t.children[0]._decode(e));var r,i=t["default"],n=!0;if(null!==t.key&&(r=e.enterKey(t.key)),t.optional&&(n=this._peekTag(e,null!==t.explicit?t.explicit:null!==t.implicit?t.implicit:t.tag||0),e.isError(n)))return n;var a;if(t.obj&&n&&(a=e.enterObject()),n){if(null!==t.explicit){var o=this._decodeTag(e,t.explicit);if(e.isError(o))return o;e=o}if(null===t.use&&null===t.choice){if(t.any)var s=e.save();var c=this._decodeTag(e,null!==t.implicit?t.implicit:t.tag,t.any);if(e.isError(c))return c;t.any?i=e.raw(s):e=c}if(i=t.any?i:null===t.choice?this._decodeGeneric(t.tag,e):this._decodeChoice(e),e.isError(i))return i;if(!t.any&&null===t.choice&&null!==t.children){var f=t.children.some(function(t){t._decode(e)});if(f)return err}}return t.obj&&n&&(i=e.leaveObject(a)),null===t.key||null===i&&n!==!0||e.leaveKey(r,t.key,i),i},i.prototype._decodeGeneric=function(e,t){var r=this._baseState;return"seq"===e||"set"===e?null:"seqof"===e||"setof"===e?this._decodeList(t,e,r.args[0]):"octstr"===e||"bitstr"===e||"ia5str"===e?this._decodeStr(t,e):"objid"===e&&r.args?this._decodeObjid(t,r.args[0],r.args[1]):"objid"===e?this._decodeObjid(t,null,null):"gentime"===e||"utctime"===e?this._decodeTime(t,e):"null_"===e?this._decodeNull(t):"bool"===e?this._decodeBool(t):"int"===e||"enum"===e?this._decodeInt(t,r.args&&r.args[0]):null!==r.use?this._getUse(r.use,t._reporterState.obj)._decode(t):t.error("unknown tag: "+e)},i.prototype._getUse=function(e,t){var r=this._baseState;return r.useDecoder=this._use(e,t),o(null===r.useDecoder._baseState.parent),r.useDecoder=r.useDecoder._baseState.children[0],r.implicit!==r.useDecoder._baseState.implicit&&(r.useDecoder=r.useDecoder.clone(),r.useDecoder._baseState.implicit=r.implicit),r.useDecoder},i.prototype._decodeChoice=function(e){var t=this._baseState,r=null,i=!1;return Object.keys(t.choice).some(function(n){var a=e.save(),o=t.choice[n];try{var s=o._decode(e);if(e.isError(s))return!1;r={type:n,value:s},i=!0}catch(c){return e.restore(a),!1}return!0},this),i?r:e.error("Choice not matched")},i.prototype._createEncoderBuffer=function(e){return new a(e,this.reporter)},i.prototype._encode=function(e,t,r){var i=this._baseState;if(null===i["default"]||i["default"]!==e){var n=this._encodeValue(e,t,r);if(void 0!==n&&!this._skipDefault(n,t,r))return n}},i.prototype._encodeValue=function(e,t,r){var i=this._baseState;if(null===i.parent)return i.children[0]._encode(e,t||new n);var a=null;if(this.reporter=t,i.optional&&void 0===e){if(null===i["default"])return;e=i["default"]}var o=null,s=!1;if(i.any)a=this._createEncoderBuffer(e);else if(i.choice)a=this._encodeChoice(e,t);else if(i.children)o=i.children.map(function(r){if("null_"===r._baseState.tag)return r._encode(null,t,e);if(null===r._baseState.key)return t.error("Child should have a key");var i=t.enterKey(r._baseState.key);if("object"!=typeof e)return t.error("Child expected, but input is not object");var n=r._encode(e[r._baseState.key],t,e);return t.leaveKey(i),n},this).filter(function(e){return e}),o=this._createEncoderBuffer(o);else if("seqof"===i.tag||"setof"===i.tag){if(!i.args||1!==i.args.length)return t.error("Too many args for : "+i.tag);if(!Array.isArray(e))return t.error("seqof/setof, but data is not Array");var c=this.clone();c._baseState.implicit=null,o=this._createEncoderBuffer(e.map(function(r){var i=this._baseState;return this._getUse(i.args[0],e)._encode(r,t)},c))}else null!==i.use?a=this._getUse(i.use,r)._encode(e,t):(o=this._encodePrimitive(i.tag,e),s=!0);var a;if(!i.any&&null===i.choice){var f=null!==i.implicit?i.implicit:i.tag,d=null===i.implicit?"universal":"context";null===f?null===i.use&&t.error("Tag could be ommited only for .use()"):null===i.use&&(a=this._encodeComposite(f,s,d,o))}return null!==i.explicit&&(a=this._encodeComposite(i.explicit,!1,"context",a)),a},i.prototype._encodeChoice=function(e,t){var r=this._baseState,i=r.choice[e.type];return i||o(!1,e.type+" not found in "+JSON.stringify(Object.keys(r.choice))),i._encode(e.value,t)},i.prototype._encodePrimitive=function(e,t){var r=this._baseState;if("octstr"===e||"bitstr"===e||"ia5str"===e)return this._encodeStr(t,e);if("objid"===e&&r.args)return this._encodeObjid(t,r.reverseArgs[0],r.args[1]);if("objid"===e)return this._encodeObjid(t,null,null);if("gentime"===e||"utctime"===e)return this._encodeTime(t,e);if("null_"===e)return this._encodeNull();if("int"===e||"enum"===e)return this._encodeInt(t,r.args&&r.reverseArgs[0]);if("bool"===e)return this._encodeBool(t);throw new Error("Unsupported tag: "+e)}},{"../base":65,"minimalistic-assert":74}],67:[function(e,t,r){function i(e){this._reporterState={obj:null,path:[],options:e||{},errors:[]}}function n(e,t){this.path=e,this.rethrow(t)}var a=e("inherits");r.Reporter=i,i.prototype.isError=function(e){return e instanceof n},i.prototype.enterKey=function(e){return this._reporterState.path.push(e)},i.prototype.leaveKey=function(e,t,r){var i=this._reporterState;i.path=i.path.slice(0,e-1),null!==i.obj&&(i.obj[t]=r)},i.prototype.enterObject=function(){var e=this._reporterState,t=e.obj;return e.obj={},t},i.prototype.leaveObject=function(e){var t=this._reporterState,r=t.obj;return t.obj=e,r},i.prototype.error=function(e){var t,r=this._reporterState,i=e instanceof n;if(t=i?e:new n(r.path.map(function(e){return"["+JSON.stringify(e)+"]"}).join(""),e.message||e,e.stack),!r.options.partial)throw t;return i||r.errors.push(t),t},i.prototype.wrapResult=function(e){var t=this._reporterState;return t.options.partial?{result:this.isError(e)?null:e,errors:t.errors}:e},a(n,Error),n.prototype.rethrow=function(e){return this.message=e+" at: "+(this.path||"(shallow)"),Error.captureStackTrace(this,n),this}},{inherits:151}],68:[function(e,t,r){var i=e("../constants");r.tagClass={0:"universal",1:"application",2:"context",3:"private"},r.tagClassByName=i._reverse(r.tagClass),r.tag={0:"end",1:"bool",2:"int",3:"bitstr",4:"octstr",5:"null_",6:"objid",7:"objDesc",8:"external",9:"real",10:"enum",11:"embed",12:"utf8str",13:"relativeOid",16:"seq",17:"set",18:"numstr",19:"printstr",20:"t61str",21:"videostr",22:"ia5str",23:"utctime",24:"gentime",25:"graphstr",26:"iso646str",27:"genstr",28:"unistr",29:"charstr",30:"bmpstr"},r.tagByName=i._reverse(r.tag)},{"../constants":69}],69:[function(e,t,r){var i=r;i._reverse=function(e){var t={};return Object.keys(e).forEach(function(r){(0|r)==r&&(r=0|r);var i=e[r];t[i]=r}),t},i.der=e("./der")},{"./der":68}],70:[function(e,t,r){function i(e){this.enc="der",this.name=e.name,this.entity=e,this.tree=new n,this.tree._init(e.body)}function n(e){f.Node.call(this,"der",e)}function a(e,t){var r=e.readUInt8(t);if(e.isError(r))return r;var i=u.tagClass[r>>6],n=0===(32&r);if(31===(31&r)){var a=r;for(r=0;128===(128&a);){if(a=e.readUInt8(t),e.isError(a))return a;r<<=7,r|=127&a}}else r&=31;var o=u.tag[r];return{cls:i,primitive:n,tag:r,tagStr:o}}function o(e,t,r){var i=e.readUInt8(r);if(e.isError(i))return i;if(!t&&128===i)return null;if(0===(128&i))return i;var n=127&i;if(n>=4)return e.error("length octect is too long");i=0;for(var a=0;n>a;a++){i<<=8;var o=e.readUInt8(r);if(e.isError(o))return o;i|=o}return i}var s=e("inherits"),c=e("../../asn1"),f=c.base,d=c.bignum,u=c.constants.der;t.exports=i,i.prototype.decode=function(e,t){return e instanceof f.DecoderBuffer||(e=new f.DecoderBuffer(e,t)),this.tree._decode(e,t)},s(n,f.Node),n.prototype._peekTag=function(e,t){if(e.isEmpty())return!1;var r=e.save(),i=a(e,'Failed to peek tag: "'+t+'"');return e.isError(i)?i:(e.restore(r),i.tag===t||i.tagStr===t)},n.prototype._decodeTag=function(e,t,r){var i=a(e,'Failed to decode tag of "'+t+'"');if(e.isError(i))return i;var n=o(e,i.primitive,'Failed to get length of "'+t+'"');if(e.isError(n))return n;if(!r&&i.tag!==t&&i.tagStr!==t&&i.tagStr+"of"!==t)return e.error('Failed to match tag: "'+t+'"');if(i.primitive||null!==n)return e.skip(n,'Failed to match body of: "'+t+'"');var s=e.start(),c=this._skipUntilEnd(e,'Failed to skip indefinite length body: "'+this.tag+'"');return e.isError(c)?c:e.cut(s)},n.prototype._skipUntilEnd=function(e,t){for(;;){var r=a(e,t);if(e.isError(r))return r;var i=o(e,r.primitive,t);if(e.isError(i))return i;var n;if(n=r.primitive||null!==i?e.skip(i):this._skipUntilEnd(e,t),e.isError(n))return n;if("end"===r.tagStr)break}},n.prototype._decodeList=function(e,t,r){for(var i=[];!e.isEmpty();){var n=this._peekTag(e,"end");if(e.isError(n))return n;var a=r.decode(e,"der");if(e.isError(a)&&n)break;i.push(a)}return i},n.prototype._decodeStr=function(e,t){if("octstr"===t)return e.raw();if("bitstr"===t){var r=e.readUInt8();return e.isError(r)?r:{unused:r,data:e.raw()}}return"ia5str"===t?e.raw().toString():this.error("Decoding of string type: "+t+" unsupported")},n.prototype._decodeObjid=function(e,t,r){for(var i=[],n=0;!e.isEmpty();){var a=e.readUInt8();n<<=7,n|=127&a,0===(128&a)&&(i.push(n),n=0)}128&a&&i.push(n);var o=i[0]/40|0,s=i[0]%40;return result=r?i:[o,s].concat(i.slice(1)),t&&(result=t[result.join(" ")]),result},n.prototype._decodeTime=function(e,t){var r=e.raw().toString();if("gentime"===t)var i=0|r.slice(0,4),n=0|r.slice(4,6),a=0|r.slice(6,8),o=0|r.slice(8,10),s=0|r.slice(10,12),c=0|r.slice(12,14);else{if("utctime"!==t)return this.error("Decoding "+t+" time is not supported yet");var i=0|r.slice(0,2),n=0|r.slice(2,4),a=0|r.slice(4,6),o=0|r.slice(6,8),s=0|r.slice(8,10),c=0|r.slice(10,12);i=70>i?2e3+i:1900+i}return Date.UTC(i,n-1,a,o,s,c,0)},n.prototype._decodeNull=function(e){return null},n.prototype._decodeBool=function(e){var t=e.readUInt8();return e.isError(t)?t:0!==t},n.prototype._decodeInt=function(e,t){var r=0,i=e.raw();if(i.length>3)return new d(i);for(;!e.isEmpty();){r<<=8;var n=e.readUInt8();if(e.isError(n))return n;r|=n}return t&&(r=t[r]||r),r},n.prototype._use=function(e,t){return"function"==typeof e&&(e=e(t)),e._getDecoder("der").tree}},{"../../asn1":62,inherits:151}],71:[function(e,t,r){var i=r;i.der=e("./der")},{"./der":70}],72:[function(e,t,r){function i(e){this.enc="der",this.name=e.name,this.entity=e,this.tree=new n,this.tree._init(e.body)}function n(e){d.Node.call(this,"der",e)}function a(e){return 10>=e?"0"+e:e}function o(e,t,r,i){var n;if("seqof"===e?e="seq":"setof"===e&&(e="set"),h.tagByName.hasOwnProperty(e))n=h.tagByName[e];else{if("number"!=typeof e||(0|e)!==e)return i.error("Unknown tag: "+e);n=e}return n>=31?i.error("Multi-octet tag encoding unsupported"):(t||(n|=32),n|=h.tagClassByName[r||"universal"]<<6)}var s=e("inherits"),c=e("buffer").Buffer,f=e("../../asn1"),d=f.base,u=f.bignum,h=f.constants.der;t.exports=i,i.prototype.encode=function(e,t){return this.tree._encode(e,t).join()},s(n,d.Node),n.prototype._encodeComposite=function(e,t,r,i){var n=o(e,t,r,this.reporter);if(i.length<128){var a=new c(2);return a[0]=n,a[1]=i.length,this._createEncoderBuffer([a,i])}for(var s=1,f=i.length;f>=256;f>>=8)s++;var a=new c(2+s);a[0]=n,a[1]=128|s;for(var f=1+s,d=i.length;d>0;f--,d>>=8)a[f]=255&d;return this._createEncoderBuffer([a,i])},n.prototype._encodeStr=function(e,t){return"octstr"===t?this._createEncoderBuffer(e):"bitstr"===t?this._createEncoderBuffer([0|e.unused,e.data]):"ia5str"===t?this._createEncoderBuffer(e):this.reporter.error("Encoding of string type: "+t+" unsupported")},n.prototype._encodeObjid=function(e,t,r){if("string"==typeof e){if(!t)return this.reporter.error("string objid given, but no values map found");if(!t.hasOwnProperty(e))return this.reporter.error("objid not found in values map");e=t[e].split(/\s+/g);for(var i=0;i<e.length;i++)e[i]|=0}else Array.isArray(e)&&(e=e.slice());if(!Array.isArray(e))return this.reporter.error("objid() should be either array or string, got: "+JSON.stringify(e));if(!r){if(e[1]>=40)return this.reporter.error("Second objid identifier OOB");e.splice(0,2,40*e[0]+e[1])}for(var n=0,i=0;i<e.length;i++){var a=e[i];for(n++;a>=128;a>>=7)n++}for(var o=new c(n),s=o.length-1,i=e.length-1;i>=0;i--){var a=e[i];for(o[s--]=127&a;(a>>=7)>0;)o[s--]=128|127&a}return this._createEncoderBuffer(o)},n.prototype._encodeTime=function(e,t){var r,i=new Date(e);return"gentime"===t?r=[i.getFullYear(),a(i.getUTCMonth()+1),a(i.getUTCDate()),a(i.getUTCHours()),a(i.getUTCMinutes()),a(i.getUTCSeconds()),"Z"].join(""):"utctime"===t?r=[i.getFullYear()%100,a(i.getUTCMonth()+1),a(i.getUTCDate()),a(i.getUTCHours()),a(i.getUTCMinutes()),a(i.getUTCSeconds()),"Z"].join(""):this.reporter.error("Encoding "+t+" time is not supported yet"),this._encodeStr(r,"octstr")},n.prototype._encodeNull=function(){return this._createEncoderBuffer("")},n.prototype._encodeInt=function(e,t){if("string"==typeof e){if(!t)return this.reporter.error("String int or enum given, but no values map");if(!t.hasOwnProperty(e))return this.reporter.error("Values map doesn't contain: "+JSON.stringify(e));e=t[e]}if(null!==u&&e instanceof u){var r=e.toArray();e.sign===!1&&128&r[0]&&r.unshift(0),e=new c(r)}if(c.isBuffer(e)){var i=e.length;0===e.length&&i++;var n=new c(i);return e.copy(n),0===e.length&&(n[0]=0),this._createEncoderBuffer(n)}if(128>e)return this._createEncoderBuffer(e);if(256>e)return this._createEncoderBuffer([0,e]);for(var i=1,a=e;a>=256;a>>=8)i++;for(var n=new Array(i),a=n.length-1;a>=0;a--)n[a]=255&e,e>>=8;return 128&n[0]&&n.unshift(0),this._createEncoderBuffer(new c(n))},n.prototype._encodeBool=function(e){return this._createEncoderBuffer(e?255:0)},n.prototype._use=function(e,t){return"function"==typeof e&&(e=e(t)),e._getEncoder("der").tree},n.prototype._skipDefault=function(e,t,r){var i,n=this._baseState;if(null===n["default"])return!1;var a=e.join();if(void 0===n.defaultBuffer&&(n.defaultBuffer=this._encodeValue(n["default"],t,r).join()),a.length!==n.defaultBuffer.length)return!1;for(i=0;i<a.length;i++)if(a[i]!==n.defaultBuffer[i])return!1;return!0}},{"../../asn1":62,buffer:9,inherits:151}],73:[function(e,t,r){var i=r;i.der=e("./der")},{"./der":72}],74:[function(e,t,r){function i(e,t){if(!e)throw new Error(t||"Assertion failed")}t.exports=i,i.equal=function(e,t,r){if(e!=t)throw new Error(r||"Assertion failed: "+e+" != "+t)}},{}],75:[function(e,t,r){(function(t){function i(e,t,r,i,a,o){if("function"==typeof a&&(o=a,a=void 0),"function"!=typeof o)throw new Error("No callback provided to pbkdf2");var s=n(e,t,r,i,a);setTimeout(function(){o(void 0,s)})}function n(e,r,i,n,o){if("number"!=typeof i)throw new TypeError("Iterations not a number");if(0>i)throw new TypeError("Bad iterations");if("number"!=typeof n)throw new TypeError("Key length not a number");if(0>n)throw new TypeError("Bad key length");o=o||"sha1",t.isBuffer(e)||(e=new t(e)),t.isBuffer(r)||(r=new t(r));var s,c=1,f=new t(n),d=new t(r.length+4);r.copy(d,0,0,r.length);for(var u,h,l=1;c>=l;l++){d.writeUInt32BE(l,r.length);var b=a(o,e).update(d).digest();if(!s&&(s=b.length,h=new t(s),c=Math.ceil(n/s),u=n-(c-1)*s,n>(Math.pow(2,32)-1)*s))throw new TypeError("keylen exceeds maximum length");b.copy(h,0,0,s);for(var p=1;i>p;p++){b=a(o,e).update(b).digest();for(var m=0;s>m;m++)h[m]^=b[m]}var g=(l-1)*s,v=l===c?u:s;h.copy(f,g,0,v)}return f}var a=e("create-hmac");r.pbkdf2=i,r.pbkdf2Sync=n}).call(this,e("buffer").Buffer)},{buffer:9,"create-hmac":113}],76:[function(e,t,r){(function(r){function i(e,t,r,i){var o=h(t);if(o.curve){if("ecdsa"!==i)throw new Error("wrong public key type");return n(e,o)}if("dsa"===o.type)return a(e,o,r);if("rsa"!==i)throw new Error("wrong public key type");for(var s=o.modulus.byteLength(),c=[0,1];e.length+c.length+1<s;)c.push(255);c.push(0);for(var f=-1;++f<e.length;)c.push(e[f]);var d=p(c,o);return d}function n(e,t){var i=g[t.curve.join(".")];if(!i)throw new Error("unknown curve "+t.curve.join("."));var n=new b.ec(i),a=n.genKeyPair();a._importPrivate(t.privateKey);var o=a.sign(e);return new r(o.toDER())}function a(e,t,r){for(var i,n=t.params.priv_key,a=t.params.p,f=t.params.q,h=(l.mont(f),t.params.g),b=new l(0),p=c(e,f).mod(f),m=!1,g=s(n,f,e,r);m===!1;)i=d(f,g,r),b=u(h,i,a,f),m=i.invm(f).imul(p.add(n.mul(b))).mod(f),m.cmpn(0)||(m=!1,b=new l(0));return o(b,m)}function o(e,t){e=e.toArray(),t=t.toArray(),128&e[0]&&(e=[0].concat(e)),128&t[0]&&(t=[0].concat(t));var i=e.length+t.length+4,n=[48,i,2,e.length];return n=n.concat(e,[2,t.length],t),new r(n)}function s(e,t,i,n){if(e=new r(e.toArray()),e.length<t.byteLength()){var a=new r(t.byteLength()-e.length);a.fill(0),e=r.concat([a,e])}var o=i.length,s=f(i,t),c=new r(o);c.fill(1);var d=new r(o);return d.fill(0),d=m(n,d).update(c).update(new r([0])).update(e).update(s).digest(),c=m(n,d).update(c).digest(),d=m(n,d).update(c).update(new r([1])).update(e).update(s).digest(),c=m(n,d).update(c).digest(),{k:d,v:c}}function c(e,t){var r=new l(e),i=(e.length<<3)-t.bitLength();return i>0&&r.ishrn(i),r}function f(e,t){e=c(e,t),e=e.mod(t);var i=new r(e.toArray());if(i.length<t.byteLength()){var n=new r(t.byteLength()-i.length);n.fill(0),i=r.concat([n,i])}return i}function d(e,t,i){for(var n,a;;){for(n=new r("");8*n.length<e.bitLength();)t.v=m(i,t.k).update(t.v).digest(),n=r.concat([n,t.v]);if(a=c(n,e),t.k=m(i,t.k).update(t.v).update(new r([0])).digest(),t.v=m(i,t.k).update(t.v).digest(),-1===a.cmp(e))return a}}function u(e,t,r,i){return e.toRed(l.mont(r)).redPow(t).fromRed().mod(i)}var h=e("parse-asn1"),l=e("bn.js"),b=e("elliptic"),p=e("browserify-rsa"),m=e("create-hmac"),g=e("./curves");t.exports=i,t.exports.getKey=s,t.exports.makeKey=d}).call(this,e("buffer").Buffer)},{"./curves":34,"bn.js":35,"browserify-rsa":36,buffer:9,"create-hmac":113,elliptic:37,"parse-asn1":61}],77:[function(e,t,r){(function(r){"use strict";function i(e,t,i,o){var c=s(i);if("ec"===c.type){if("ecdsa"!==o)throw new Error("wrong public key type");return n(e,t,c)}if("dsa"===c.type){if("dsa"!==o)throw new Error("wrong public key type");return a(e,t,c)}if("rsa"!==o)throw new Error("wrong public key type");for(var f=c.modulus.byteLength(),u=[1],h=0;t.length+u.length+2<f;)u.push(255),h++;u.push(0);for(var l=-1;++l<t.length;)u.push(t[l]);u=new r(u);var b=d.mont(c.modulus);e=new d(e).toRed(b),e=e.redPow(new d(c.publicExponent)),e=new r(e.fromRed().toArray());var p=0;for(8>h&&(p=1),f=Math.min(e.length,u.length),e.length!==u.length&&(p=1),l=-1;++l<f;)p|=e[l]^u[l];return 0===p}function n(e,t,r){var i=f[r.data.algorithm.curve.join(".")];if(!i)throw new Error("unknown curve "+r.data.algorithm.curve.join("."));var n=new c.ec(i),a=r.data.subjectPrivateKey.data;return n.verify(t.toString("hex"),e.toString("hex"),a.toString("hex"))}function a(e,t,r){var i=r.data.p,n=r.data.q,a=r.data.g,c=r.data.pub_key,f=s.signature.decode(e,"der"),u=f.s,h=f.r;o(u,n),o(h,n);var l=(d.mont(n),d.mont(i)),b=u.invm(n),p=a.toRed(l).redPow(new d(t).mul(b).mod(n)).fromRed().mul(c.toRed(l).redPow(h.mul(b).mod(n)).fromRed()).mod(i).mod(n);return!p.cmp(h)}function o(e,t){if(e.cmpn(0)<=0)throw new Error("invalid sig");if(e.cmp(t)>=t)throw new Error("invalid sig")}var s=e("parse-asn1"),c=e("elliptic"),f=e("./curves"),d=e("bn.js");t.exports=i}).call(this,e("buffer").Buffer)},{"./curves":34,"bn.js":35,buffer:9,elliptic:37,"parse-asn1":61}],78:[function(e,t,r){(function(r){function i(e){this.curveType=s[e],this.curveType||(this.curveType={name:e}),this.curve=new a.ec(this.curveType.name),this.keys=void 0}function n(e,t,i){Array.isArray(e)||(e=e.toArray());var n=new r(e);if(i&&n.length<i){var a=new r(i-n.length);a.fill(0),n=r.concat([a,n])}return t?n.toString(t):n}var a=e("elliptic"),o=e("bn.js");t.exports=function(e){return new i(e)};var s={secp256k1:{name:"secp256k1",byteLength:32},secp224r1:{name:"p224",byteLength:28},prime256v1:{name:"p256",byteLength:32},prime192v1:{name:"p192",byteLength:24},ed25519:{name:"ed25519",byteLength:32}};s.p224=s.secp224r1,s.p256=s.secp256r1=s.prime256v1,s.p192=s.secp192r1=s.prime192v1,i.prototype.generateKeys=function(e,t){return this.keys=this.curve.genKeyPair(),this.getPublicKey(e,t)},i.prototype.computeSecret=function(e,t,i){t=t||"utf8",r.isBuffer(e)||(e=new r(e,t)),e=new o(e),e=e.toString(16);var a=this.curve.keyPair(e,"hex").getPublic(),s=a.mul(this.keys.getPrivate()).getX();return n(s,i,this.curveType.byteLength)},i.prototype.getPublicKey=function(e,t){var r=this.keys.getPublic("compressed"===t,!0);return"hybrid"===t&&(r[0]=r[r.length-1]%2?7:6),n(r,e)},i.prototype.getPrivateKey=function(e){return n(this.keys.getPrivate(),e)},i.prototype.setPublicKey=function(e,t){t=t||"utf8",r.isBuffer(e)||(e=new r(e,t));var i=new o(e);return i=i.toArray(),this.keys._importPublicHex(i),this},i.prototype.setPrivateKey=function(e,t){t=t||"utf8",r.isBuffer(e)||(e=new r(e,t));var i=new o(e);return i=i.toString(16),this.keys._importPrivate(i),this}}).call(this,e("buffer").Buffer)},{"bn.js":80,buffer:9,elliptic:81}],79:[function(e,t,r){var i=e("crypto").createECDH;t.exports=i||e("./browser")},{"./browser":78,crypto:13}],80:[function(e,t,r){t.exports=e(35)},{"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/bn.js/lib/bn.js":35}],81:[function(e,t,r){t.exports=e(37)},{"../package.json":100,"./elliptic/curve":84,"./elliptic/curves":87,"./elliptic/ec":88,"./elliptic/hmac-drbg":91,"./elliptic/utils":92,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/lib/elliptic.js":37,brorand:93}],82:[function(e,t,r){t.exports=e(38)},{"../../elliptic":81,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/lib/elliptic/curve/base.js":38,"bn.js":80}],83:[function(e,t,r){t.exports=e(39)},{"../../elliptic":81,"../curve":84,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/lib/elliptic/curve/edwards.js":39,"bn.js":80,inherits:151}],84:[function(e,t,r){t.exports=e(40)},{"./base":82,"./edwards":83,"./mont":85,"./short":86,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/lib/elliptic/curve/index.js":40}],85:[function(e,t,r){t.exports=e(41)},{"../../elliptic":81,"../curve":84,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/lib/elliptic/curve/mont.js":41,"bn.js":80,inherits:151}],86:[function(e,t,r){t.exports=e(42)},{"../../elliptic":81,"../curve":84,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/lib/elliptic/curve/short.js":42,"bn.js":80,inherits:151}],87:[function(e,t,r){t.exports=e(43)},{"../elliptic":81,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/lib/elliptic/curves.js":43,"bn.js":80,"hash.js":94}],88:[function(e,t,r){t.exports=e(44)},{"../../elliptic":81,"./key":89,"./signature":90,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/lib/elliptic/ec/index.js":44,"bn.js":80}],89:[function(e,t,r){t.exports=e(45)},{"../../elliptic":81,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/lib/elliptic/ec/key.js":45,"bn.js":80}],90:[function(e,t,r){t.exports=e(46)},{"../../elliptic":81,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/lib/elliptic/ec/signature.js":46,"bn.js":80}],91:[function(e,t,r){t.exports=e(47)},{"../elliptic":81,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/lib/elliptic/hmac-drbg.js":47,"hash.js":94}],92:[function(e,t,r){t.exports=e(48)},{"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/lib/elliptic/utils.js":48,"bn.js":80}],93:[function(e,t,r){t.exports=e(49)},{"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/node_modules/brorand/index.js":49}],94:[function(e,t,r){t.exports=e(50)},{"./hash/common":95,"./hash/hmac":96,"./hash/ripemd":97,"./hash/sha":98,"./hash/utils":99,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/node_modules/hash.js/lib/hash.js":50}],95:[function(e,t,r){t.exports=e(51)},{"../hash":94,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/node_modules/hash.js/lib/hash/common.js":51}],96:[function(e,t,r){t.exports=e(52)},{"../hash":94,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/node_modules/hash.js/lib/hash/hmac.js":52}],97:[function(e,t,r){t.exports=e(53);

},{"../hash":94,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/node_modules/hash.js/lib/hash/ripemd.js":53}],98:[function(e,t,r){t.exports=e(54)},{"../hash":94,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/node_modules/hash.js/lib/hash/sha.js":54}],99:[function(e,t,r){t.exports=e(55)},{"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/node_modules/hash.js/lib/hash/utils.js":55,inherits:151}],100:[function(e,t,r){t.exports=e(56)},{"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/package.json":56}],101:[function(e,t,r){(function(r){"use strict";function i(e){f.call(this),this._hash=e,this.buffers=[]}function n(e){f.call(this),this._hash=e}var a=e("inherits"),o=e("./md5"),s=e("ripemd160"),c=e("sha.js"),f=e("stream").Transform;a(i,f),i.prototype._transform=function(e,t,r){this.buffers.push(e),r()},i.prototype._flush=function(e){this.push(this.digest()),e()},i.prototype.update=function(e,t){return"string"==typeof e&&(e=new r(e,t)),this.buffers.push(e),this},i.prototype.digest=function(e){var t=r.concat(this.buffers),i=this._hash(t);return this.buffers=null,e?i.toString(e):i},a(n,f),n.prototype._transform=function(e,t,i){t&&(e=new r(e,t)),this._hash.update(e),i()},n.prototype._flush=function(e){this.push(this._hash.digest()),this._hash=null,e()},n.prototype.update=function(e,t){return"string"==typeof e&&(e=new r(e,t)),this._hash.update(e),this},n.prototype.digest=function(e){var t=this._hash.digest();return e?t.toString(e):t},t.exports=function(e){return"md5"===e?new i(o):"rmd160"===e?new i(s):new n(c(e))}}).call(this,e("buffer").Buffer)},{"./md5":103,buffer:9,inherits:151,ripemd160:104,"sha.js":106,stream:165}],102:[function(e,t,r){(function(e){"use strict";function t(t,r){if(t.length%a!==0){var i=t.length+(a-t.length%a);t=e.concat([t,o],i)}for(var n=[],s=r?t.readInt32BE:t.readInt32LE,c=0;c<t.length;c+=a)n.push(s.call(t,c));return n}function i(t,r,i){for(var n=new e(r),a=i?n.writeInt32BE:n.writeInt32LE,o=0;o<t.length;o++)a.call(n,t[o],4*o,!0);return n}function n(r,n,a,o){e.isBuffer(r)||(r=new e(r));var c=n(t(r,o),r.length*s);return i(c,a,o)}var a=4,o=new e(a);o.fill(0);var s=8;r.hash=n}).call(this,e("buffer").Buffer)},{buffer:9}],103:[function(e,t,r){"use strict";function i(e,t){e[t>>5]|=128<<t%32,e[(t+64>>>9<<4)+14]=t;for(var r=1732584193,i=-271733879,n=-1732584194,d=271733878,u=0;u<e.length;u+=16){var h=r,l=i,b=n,p=d;r=a(r,i,n,d,e[u+0],7,-680876936),d=a(d,r,i,n,e[u+1],12,-389564586),n=a(n,d,r,i,e[u+2],17,606105819),i=a(i,n,d,r,e[u+3],22,-1044525330),r=a(r,i,n,d,e[u+4],7,-176418897),d=a(d,r,i,n,e[u+5],12,1200080426),n=a(n,d,r,i,e[u+6],17,-1473231341),i=a(i,n,d,r,e[u+7],22,-45705983),r=a(r,i,n,d,e[u+8],7,1770035416),d=a(d,r,i,n,e[u+9],12,-1958414417),n=a(n,d,r,i,e[u+10],17,-42063),i=a(i,n,d,r,e[u+11],22,-1990404162),r=a(r,i,n,d,e[u+12],7,1804603682),d=a(d,r,i,n,e[u+13],12,-40341101),n=a(n,d,r,i,e[u+14],17,-1502002290),i=a(i,n,d,r,e[u+15],22,1236535329),r=o(r,i,n,d,e[u+1],5,-165796510),d=o(d,r,i,n,e[u+6],9,-1069501632),n=o(n,d,r,i,e[u+11],14,643717713),i=o(i,n,d,r,e[u+0],20,-373897302),r=o(r,i,n,d,e[u+5],5,-701558691),d=o(d,r,i,n,e[u+10],9,38016083),n=o(n,d,r,i,e[u+15],14,-660478335),i=o(i,n,d,r,e[u+4],20,-405537848),r=o(r,i,n,d,e[u+9],5,568446438),d=o(d,r,i,n,e[u+14],9,-1019803690),n=o(n,d,r,i,e[u+3],14,-187363961),i=o(i,n,d,r,e[u+8],20,1163531501),r=o(r,i,n,d,e[u+13],5,-1444681467),d=o(d,r,i,n,e[u+2],9,-51403784),n=o(n,d,r,i,e[u+7],14,1735328473),i=o(i,n,d,r,e[u+12],20,-1926607734),r=s(r,i,n,d,e[u+5],4,-378558),d=s(d,r,i,n,e[u+8],11,-2022574463),n=s(n,d,r,i,e[u+11],16,1839030562),i=s(i,n,d,r,e[u+14],23,-35309556),r=s(r,i,n,d,e[u+1],4,-1530992060),d=s(d,r,i,n,e[u+4],11,1272893353),n=s(n,d,r,i,e[u+7],16,-155497632),i=s(i,n,d,r,e[u+10],23,-1094730640),r=s(r,i,n,d,e[u+13],4,681279174),d=s(d,r,i,n,e[u+0],11,-358537222),n=s(n,d,r,i,e[u+3],16,-722521979),i=s(i,n,d,r,e[u+6],23,76029189),r=s(r,i,n,d,e[u+9],4,-640364487),d=s(d,r,i,n,e[u+12],11,-421815835),n=s(n,d,r,i,e[u+15],16,530742520),i=s(i,n,d,r,e[u+2],23,-995338651),r=c(r,i,n,d,e[u+0],6,-198630844),d=c(d,r,i,n,e[u+7],10,1126891415),n=c(n,d,r,i,e[u+14],15,-1416354905),i=c(i,n,d,r,e[u+5],21,-57434055),r=c(r,i,n,d,e[u+12],6,1700485571),d=c(d,r,i,n,e[u+3],10,-1894986606),n=c(n,d,r,i,e[u+10],15,-1051523),i=c(i,n,d,r,e[u+1],21,-2054922799),r=c(r,i,n,d,e[u+8],6,1873313359),d=c(d,r,i,n,e[u+15],10,-30611744),n=c(n,d,r,i,e[u+6],15,-1560198380),i=c(i,n,d,r,e[u+13],21,1309151649),r=c(r,i,n,d,e[u+4],6,-145523070),d=c(d,r,i,n,e[u+11],10,-1120210379),n=c(n,d,r,i,e[u+2],15,718787259),i=c(i,n,d,r,e[u+9],21,-343485551),r=f(r,h),i=f(i,l),n=f(n,b),d=f(d,p)}return Array(r,i,n,d)}function n(e,t,r,i,n,a){return f(d(f(f(t,e),f(i,a)),n),r)}function a(e,t,r,i,a,o,s){return n(t&r|~t&i,e,t,a,o,s)}function o(e,t,r,i,a,o,s){return n(t&i|r&~i,e,t,a,o,s)}function s(e,t,r,i,a,o,s){return n(t^r^i,e,t,a,o,s)}function c(e,t,r,i,a,o,s){return n(r^(t|~i),e,t,a,o,s)}function f(e,t){var r=(65535&e)+(65535&t),i=(e>>16)+(t>>16)+(r>>16);return i<<16|65535&r}function d(e,t){return e<<t|e>>>32-t}var u=e("./helpers");t.exports=function(e){return u.hash(e,i,16)}},{"./helpers":102}],104:[function(e,t,r){(function(e){function r(e){for(var t=[],r=0,i=0;r<e.length;r++,i+=8)t[i>>>5]|=e[r]<<24-i%32;return t}function i(e){for(var t=[],r=0;r<32*e.length;r+=8)t.push(e[r>>>5]>>>24-r%32&255);return t}function n(e,t,r){for(var i=0;16>i;i++){var n=r+i,u=t[n];t[n]=16711935&(u<<8|u>>>24)|4278255360&(u<<24|u>>>8)}var v,y,w,_,S,k,E,x,j,A;k=v=e[0],E=y=e[1],x=w=e[2],j=_=e[3],A=S=e[4];for(var I,i=0;80>i;i+=1)I=v+t[r+h[i]]|0,I+=16>i?a(y,w,_)+m[0]:32>i?o(y,w,_)+m[1]:48>i?s(y,w,_)+m[2]:64>i?c(y,w,_)+m[3]:f(y,w,_)+m[4],I=0|I,I=d(I,b[i]),I=I+S|0,v=S,S=_,_=d(w,10),w=y,y=I,I=k+t[r+l[i]]|0,I+=16>i?f(E,x,j)+g[0]:32>i?c(E,x,j)+g[1]:48>i?s(E,x,j)+g[2]:64>i?o(E,x,j)+g[3]:a(E,x,j)+g[4],I=0|I,I=d(I,p[i]),I=I+A|0,k=A,A=j,j=d(x,10),x=E,E=I;I=e[1]+w+j|0,e[1]=e[2]+_+A|0,e[2]=e[3]+S+k|0,e[3]=e[4]+v+E|0,e[4]=e[0]+y+x|0,e[0]=I}function a(e,t,r){return e^t^r}function o(e,t,r){return e&t|~e&r}function s(e,t,r){return(e|~t)^r}function c(e,t,r){return e&r|t&~r}function f(e,t,r){return e^(t|~r)}function d(e,t){return e<<t|e>>>32-t}function u(t){var a=[1732584193,4023233417,2562383102,271733878,3285377520];"string"==typeof t&&(t=new e(t,"utf8"));var o=r(t),s=8*t.length,c=8*t.length;o[s>>>5]|=128<<24-s%32,o[(s+64>>>9<<4)+14]=16711935&(c<<8|c>>>24)|4278255360&(c<<24|c>>>8);for(var f=0;f<o.length;f+=16)n(a,o,f);for(var f=0;5>f;f++){var d=a[f];a[f]=16711935&(d<<8|d>>>24)|4278255360&(d<<24|d>>>8)}var u=i(a);return new e(u)}var h=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13],l=[5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11],b=[11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6],p=[8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11],m=[0,1518500249,1859775393,2400959708,2840853838],g=[1352829926,1548603684,1836072691,2053994217,0];t.exports=u}).call(this,e("buffer").Buffer)},{buffer:9}],105:[function(e,t,r){(function(e){function r(t,r){this._block=new e(t),this._finalSize=r,this._blockSize=t,this._len=0,this._s=0}r.prototype.update=function(t,r){"string"==typeof t&&(r=r||"utf8",t=new e(t,r));for(var i=this._len+=t.length,n=this._s||0,a=0,o=this._block;i>n;){for(var s=Math.min(t.length,a+this._blockSize-n%this._blockSize),c=s-a,f=0;c>f;f++)o[n%this._blockSize+f]=t[f+a];n+=c,a+=c,n%this._blockSize===0&&this._update(o)}return this._s=n,this},r.prototype.digest=function(e){var t=8*this._len;this._block[this._len%this._blockSize]=128,this._block.fill(0,this._len%this._blockSize+1),t%(8*this._blockSize)>=8*this._finalSize&&(this._update(this._block),this._block.fill(0)),this._block.writeInt32BE(t,this._blockSize-4);var r=this._update(this._block)||this._hash();return e?r.toString(e):r},r.prototype._update=function(){throw new Error("_update must be implemented by subclass")},t.exports=r}).call(this,e("buffer").Buffer)},{buffer:9}],106:[function(e,t,r){var r=t.exports=function(e){var t=r[e.toLowerCase()];if(!t)throw new Error(e+" is not supported (we accept pull requests)");return new t};r.sha=e("./sha"),r.sha1=e("./sha1"),r.sha224=e("./sha224"),r.sha256=e("./sha256"),r.sha384=e("./sha384"),r.sha512=e("./sha512")},{"./sha":107,"./sha1":108,"./sha224":109,"./sha256":110,"./sha384":111,"./sha512":112}],107:[function(e,t,r){(function(r){function i(){this.init(),this._w=s,o.call(this,64,56)}function n(e,t){return e<<t|e>>>32-t}var a=e("inherits"),o=e("./hash"),s=new Array(80);a(i,o),i.prototype.init=function(){return this._a=1732584193,this._b=4023233417,this._c=2562383102,this._d=271733878,this._e=3285377520,this},i.prototype._update=function(e){function t(){return a[u-3]^a[u-8]^a[u-14]^a[u-16]}function r(e,t){a[u]=e;var r=n(o,5)+t+d+e+i;d=f,f=c,c=n(s,30),s=o,o=r,u++}var i,a=this._w,o=this._a,s=this._b,c=this._c,f=this._d,d=this._e,u=0;for(i=1518500249;16>u;)r(e.readInt32BE(4*u),s&c|~s&f);for(;20>u;)r(t(),s&c|~s&f);for(i=1859775393;40>u;)r(t(),s^c^f);for(i=-1894007588;60>u;)r(t(),s&c|s&f|c&f);for(i=-899497514;80>u;)r(t(),s^c^f);this._a=o+this._a|0,this._b=s+this._b|0,this._c=c+this._c|0,this._d=f+this._d|0,this._e=d+this._e|0},i.prototype._hash=function(){var e=new r(20);return e.writeInt32BE(0|this._a,0),e.writeInt32BE(0|this._b,4),e.writeInt32BE(0|this._c,8),e.writeInt32BE(0|this._d,12),e.writeInt32BE(0|this._e,16),e},t.exports=i}).call(this,e("buffer").Buffer)},{"./hash":105,buffer:9,inherits:151}],108:[function(e,t,r){(function(r){function i(){this.init(),this._w=s,o.call(this,64,56)}function n(e,t){return e<<t|e>>>32-t}var a=e("inherits"),o=e("./hash"),s=new Array(80);a(i,o),i.prototype.init=function(){return this._a=1732584193,this._b=4023233417,this._c=2562383102,this._d=271733878,this._e=3285377520,this},i.prototype._update=function(e){function t(){return n(a[u-3]^a[u-8]^a[u-14]^a[u-16],1)}function r(e,t){a[u]=e;var r=n(o,5)+t+d+e+i;d=f,f=c,c=n(s,30),s=o,o=r,u++}var i,a=this._w,o=this._a,s=this._b,c=this._c,f=this._d,d=this._e,u=0;for(i=1518500249;16>u;)r(e.readInt32BE(4*u),s&c|~s&f);for(;20>u;)r(t(),s&c|~s&f);for(i=1859775393;40>u;)r(t(),s^c^f);for(i=-1894007588;60>u;)r(t(),s&c|s&f|c&f);for(i=-899497514;80>u;)r(t(),s^c^f);this._a=o+this._a|0,this._b=s+this._b|0,this._c=c+this._c|0,this._d=f+this._d|0,this._e=d+this._e|0},i.prototype._hash=function(){var e=new r(20);return e.writeInt32BE(0|this._a,0),e.writeInt32BE(0|this._b,4),e.writeInt32BE(0|this._c,8),e.writeInt32BE(0|this._d,12),e.writeInt32BE(0|this._e,16),e},t.exports=i}).call(this,e("buffer").Buffer)},{"./hash":105,buffer:9,inherits:151}],109:[function(e,t,r){(function(r){function i(){this.init(),this._w=s,o.call(this,64,56)}var n=e("inherits"),a=e("./sha256"),o=e("./hash"),s=new Array(64);n(i,a),i.prototype.init=function(){return this._a=-1056596264,this._b=914150663,this._c=812702999,this._d=-150054599,this._e=-4191439,this._f=1750603025,this._g=1694076839,this._h=-1090891868,this},i.prototype._hash=function(){var e=new r(28);return e.writeInt32BE(this._a,0),e.writeInt32BE(this._b,4),e.writeInt32BE(this._c,8),e.writeInt32BE(this._d,12),e.writeInt32BE(this._e,16),e.writeInt32BE(this._f,20),e.writeInt32BE(this._g,24),e},t.exports=i}).call(this,e("buffer").Buffer)},{"./hash":105,"./sha256":110,buffer:9,inherits:151}],110:[function(e,t,r){(function(r){function i(){this.init(),this._w=p,l.call(this,64,56)}function n(e,t){return e>>>t|e<<32-t}function a(e,t){return e>>>t}function o(e,t,r){return e&t^~e&r}function s(e,t,r){return e&t^e&r^t&r}function c(e){return n(e,2)^n(e,13)^n(e,22)}function f(e){return n(e,6)^n(e,11)^n(e,25)}function d(e){return n(e,7)^n(e,18)^a(e,3)}function u(e){return n(e,17)^n(e,19)^a(e,10)}var h=e("inherits"),l=e("./hash"),b=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298],p=new Array(64);h(i,l),i.prototype.init=function(){return this._a=1779033703,this._b=-1150833019,this._c=1013904242,this._d=-1521486534,this._e=1359893119,this._f=-1694144372,this._g=528734635,this._h=1541459225,this},i.prototype._update=function(e){function t(){return u(i[y-2])+i[y-7]+d(i[y-15])+i[y-16]}function r(e){i[y]=e;var t=v+f(p)+o(p,m,g)+b[y]+e,r=c(n)+s(n,a,h);v=g,g=m,m=p,p=l+t,l=h,h=a,a=n,n=t+r,y++}for(var i=this._w,n=0|this._a,a=0|this._b,h=0|this._c,l=0|this._d,p=0|this._e,m=0|this._f,g=0|this._g,v=0|this._h,y=0;16>y;)r(e.readInt32BE(4*y));for(;64>y;)r(t());this._a=n+this._a|0,this._b=a+this._b|0,this._c=h+this._c|0,this._d=l+this._d|0,this._e=p+this._e|0,this._f=m+this._f|0,this._g=g+this._g|0,this._h=v+this._h|0},i.prototype._hash=function(){var e=new r(32);return e.writeInt32BE(this._a,0),e.writeInt32BE(this._b,4),e.writeInt32BE(this._c,8),e.writeInt32BE(this._d,12),e.writeInt32BE(this._e,16),e.writeInt32BE(this._f,20),e.writeInt32BE(this._g,24),e.writeInt32BE(this._h,28),e},t.exports=i}).call(this,e("buffer").Buffer)},{"./hash":105,buffer:9,inherits:151}],111:[function(e,t,r){(function(r){function i(){this.init(),this._w=s,o.call(this,128,112)}var n=e("inherits"),a=e("./sha512"),o=e("./hash"),s=new Array(160);n(i,a),i.prototype.init=function(){return this._a=-876896931,this._b=1654270250,this._c=-1856437926,this._d=355462360,this._e=1731405415,this._f=-1900787065,this._g=-619958771,this._h=1203062813,this._al=-1056596264,this._bl=914150663,this._cl=812702999,this._dl=-150054599,this._el=-4191439,this._fl=1750603025,this._gl=1694076839,this._hl=-1090891868,this},i.prototype._hash=function(){function e(e,r,i){t.writeInt32BE(e,i),t.writeInt32BE(r,i+4)}var t=new r(48);return e(this._a,this._al,0),e(this._b,this._bl,8),e(this._c,this._cl,16),e(this._d,this._dl,24),e(this._e,this._el,32),e(this._f,this._fl,40),t},t.exports=i}).call(this,e("buffer").Buffer)},{"./hash":105,"./sha512":112,buffer:9,inherits:151}],112:[function(e,t,r){(function(r){function i(){this.init(),this._w=d,c.call(this,128,112)}function n(e,t,r){return e>>>r|t<<32-r}function a(e,t,r){return e&t^~e&r}function o(e,t,r){return e&t^e&r^t&r}var s=e("inherits"),c=e("./hash"),f=[1116352408,3609767458,1899447441,602891725,3049323471,3964484399,3921009573,2173295548,961987163,4081628472,1508970993,3053834265,2453635748,2937671579,2870763221,3664609560,3624381080,2734883394,310598401,1164996542,607225278,1323610764,1426881987,3590304994,1925078388,4068182383,2162078206,991336113,2614888103,633803317,3248222580,3479774868,3835390401,2666613458,4022224774,944711139,264347078,2341262773,604807628,2007800933,770255983,1495990901,1249150122,1856431235,1555081692,3175218132,1996064986,2198950837,2554220882,3999719339,2821834349,766784016,2952996808,2566594879,3210313671,3203337956,3336571891,1034457026,3584528711,2466948901,113926993,3758326383,338241895,168717936,666307205,1188179964,773529912,1546045734,1294757372,1522805485,1396182291,2643833823,1695183700,2343527390,1986661051,1014477480,2177026350,1206759142,2456956037,344077627,2730485921,1290863460,2820302411,3158454273,3259730800,3505952657,3345764771,106217008,3516065817,3606008344,3600352804,1432725776,4094571909,1467031594,275423344,851169720,430227734,3100823752,506948616,1363258195,659060556,3750685593,883997877,3785050280,958139571,3318307427,1322822218,3812723403,1537002063,2003034995,1747873779,3602036899,1955562222,1575990012,2024104815,1125592928,2227730452,2716904306,2361852424,442776044,2428436474,593698344,2756734187,3733110249,3204031479,2999351573,3329325298,3815920427,3391569614,3928383900,3515267271,566280711,3940187606,3454069534,4118630271,4000239992,116418474,1914138554,174292421,2731055270,289380356,3203993006,460393269,320620315,685471733,587496836,852142971,1086792851,1017036298,365543100,1126000580,2618297676,1288033470,3409855158,1501505948,4234509866,1607167915,987167468,1816402316,1246189591],d=new Array(160);s(i,c),i.prototype.init=function(){return this._a=1779033703,this._b=-1150833019,this._c=1013904242,this._d=-1521486534,this._e=1359893119,this._f=-1694144372,this._g=528734635,this._h=1541459225,this._al=-205731576,this._bl=-2067093701,this._cl=-23791573,this._dl=1595750129,this._el=-1377402159,this._fl=725511199,this._gl=-79577749,this._hl=327033209,this},i.prototype._update=function(e){function t(){var e=c[A-30],t=c[A-30+1],r=n(e,t,1)^n(e,t,8)^e>>>7,a=n(t,e,1)^n(t,e,8)^n(t,e,7);e=c[A-4],t=c[A-4+1];var o=n(e,t,19)^n(t,e,29)^e>>>6,f=n(t,e,19)^n(e,t,29)^n(t,e,6),d=c[A-14],u=c[A-14+1],h=c[A-32],l=c[A-32+1];s=a+u,i=r+d+(a>>>0>s>>>0?1:0),s+=f,i=i+o+(f>>>0>s>>>0?1:0),s+=l,i=i+h+(l>>>0>s>>>0?1:0)}function r(){c[A]=i,c[A+1]=s;var e=o(d,u,h),t=o(v,y,w),r=n(d,v,28)^n(v,d,2)^n(v,d,7),I=n(v,d,28)^n(d,v,2)^n(d,v,7),B=n(b,S,14)^n(b,S,18)^n(S,b,9),z=n(S,b,14)^n(S,b,18)^n(b,S,9),M=f[A],R=f[A+1],P=a(b,p,m),T=a(S,k,E),C=x+z,q=g+B+(x>>>0>C>>>0?1:0);C+=T,q=q+P+(T>>>0>C>>>0?1:0),C+=R,q=q+M+(R>>>0>C>>>0?1:0),C+=s,q=q+i+(s>>>0>C>>>0?1:0);var L=I+t,D=r+e+(I>>>0>L>>>0?1:0);g=m,x=E,m=p,E=k,p=b,k=S,S=_+C|0,b=l+q+(_>>>0>S>>>0?1:0)|0,l=h,_=w,h=u,w=y,u=d,y=v,v=C+L|0,d=q+D+(C>>>0>v>>>0?1:0)|0,j++,A+=2}for(var i,s,c=this._w,d=0|this._a,u=0|this._b,h=0|this._c,l=0|this._d,b=0|this._e,p=0|this._f,m=0|this._g,g=0|this._h,v=0|this._al,y=0|this._bl,w=0|this._cl,_=0|this._dl,S=0|this._el,k=0|this._fl,E=0|this._gl,x=0|this._hl,j=0,A=0;16>j;)i=e.readInt32BE(4*A),s=e.readInt32BE(4*A+4),r();for(;80>j;)t(),r();this._al=this._al+v|0,this._bl=this._bl+y|0,this._cl=this._cl+w|0,this._dl=this._dl+_|0,this._el=this._el+S|0,this._fl=this._fl+k|0,this._gl=this._gl+E|0,this._hl=this._hl+x|0,this._a=this._a+d+(this._al>>>0<v>>>0?1:0)|0,this._b=this._b+u+(this._bl>>>0<y>>>0?1:0)|0,this._c=this._c+h+(this._cl>>>0<w>>>0?1:0)|0,this._d=this._d+l+(this._dl>>>0<_>>>0?1:0)|0,this._e=this._e+b+(this._el>>>0<S>>>0?1:0)|0,this._f=this._f+p+(this._fl>>>0<k>>>0?1:0)|0,this._g=this._g+m+(this._gl>>>0<E>>>0?1:0)|0,this._h=this._h+g+(this._hl>>>0<x>>>0?1:0)|0},i.prototype._hash=function(){function e(e,r,i){t.writeInt32BE(e,i),t.writeInt32BE(r,i+4)}var t=new r(64);return e(this._a,this._al,0),e(this._b,this._bl,8),e(this._c,this._cl,16),e(this._d,this._dl,24),e(this._e,this._el,32),e(this._f,this._fl,40),e(this._g,this._gl,48),e(this._h,this._hl,56),t},t.exports=i}).call(this,e("buffer").Buffer)},{"./hash":105,buffer:9,inherits:151}],113:[function(e,t,r){(function(r){"use strict";function i(e,t){o.call(this),"string"==typeof t&&(t=new r(t));var i="sha512"===e||"sha384"===e?128:64;this._alg=e,this._key=t,t.length>i?t=n(e).update(t).digest():t.length<i&&(t=r.concat([t,s],i));for(var a=this._ipad=new r(i),c=this._opad=new r(i),f=0;i>f;f++)a[f]=54^t[f],c[f]=92^t[f];this._hash=n(e).update(a)}var n=e("create-hash/browser"),a=e("inherits"),o=e("stream").Transform,s=new r(128);s.fill(0),a(i,o),i.prototype.update=function(e,t){return this._hash.update(e,t),this},i.prototype._transform=function(e,t,r){this._hash.update(e),r()},i.prototype._flush=function(e){this.push(this.digest()),e()},i.prototype.digest=function(e){var t=this._hash.digest();return n(this._alg).update(this._opad).update(t).digest(e)},t.exports=function(e,t){return new i(e,t)}}).call(this,e("buffer").Buffer)},{buffer:9,"create-hash/browser":101,inherits:151,stream:165}],114:[function(e,t,r){(function(t){function i(e){var r=new t(o[e].prime,"hex"),i=new t(o[e].gen,"hex");return new s(r,i)}function n(e,r,i,n){return(t.isBuffer(r)||"string"==typeof r&&-1===["hex","binary","base64"].indexOf(r))&&(n=i,i=r,r=void 0),r=r||"binary",n=n||"binary",i=i||new t([2]),t.isBuffer(i)||(i=new t(i,n)),"number"==typeof e?new s(a(e,i),i,!0):(t.isBuffer(e)||(e=new t(e,r)),new s(e,i,!0))}var a=e("./lib/generatePrime"),o=e("./lib/primes"),s=e("./lib/dh");r.DiffieHellmanGroup=r.createDiffieHellmanGroup=r.getDiffieHellman=i,r.createDiffieHellman=r.DiffieHellman=n}).call(this,e("buffer").Buffer)},{"./lib/dh":115,"./lib/generatePrime":116,"./lib/primes":117,buffer:9}],115:[function(e,t,r){(function(r){function i(e,t){return t=t||"utf8",r.isBuffer(e)||(e=new r(e,t)),this._pub=new f(e),this}function n(e,t){return t=t||"utf8",r.isBuffer(e)||(e=new r(e,t)),this._priv=new f(e),this}function a(e,t){var r=t.toString("hex"),i=[r,e.toString(16)].join("_");if(i in y)return y[i];var n=0;if(e.isEven()||!g.simpleSieve||!g.fermatTest(e)||!u.test(e))return n+=1,n+="02"===r||"05"===r?8:4,y[i]=n,n;u.test(e.shrn(1))||(n+=2);var a;switch(r){case"02":e.mod(h).cmp(l)&&(n+=8);break;case"05":a=e.mod(b),a.cmp(p)&&a.cmp(m)&&(n+=8);break;default:n+=4}return y[i]=n,n}function o(e,t){try{Object.defineProperty(e,"verifyError",{enumerable:!0,value:t,writable:!1})}catch(r){e.verifyError=t}}function s(e,t,r){this.setGenerator(t),this.__prime=new f(e),this._prime=f.mont(this.__prime),this._primeLen=e.length,this._pub=void 0,this._priv=void 0,r?(this.setPublicKey=i,this.setPrivateKey=n,o(this,a(this.__prime,t))):o(this,8)}function c(e,t){var i=new r(e.toArray());return t?i.toString(t):i}var f=e("bn.js"),d=e("miller-rabin"),u=new d,h=new f(24),l=new f(11),b=new f(10),p=new f(3),m=new f(7),g=e("./generatePrime"),v=e("randombytes");t.exports=s;var y={};s.prototype.generateKeys=function(){return this._priv||(this._priv=new f(v(this._primeLen))),this._pub=this._gen.toRed(this._prime).redPow(this._priv).fromRed(),this.getPublicKey()},s.prototype.computeSecret=function(e){e=new f(e),e=e.toRed(this._prime);var t=e.redPow(this._priv).fromRed(),i=new r(t.toArray()),n=this.getPrime();if(i.length<n.length){var a=new r(n.length-i.length);a.fill(0),i=r.concat([a,i])}return i},s.prototype.getPublicKey=function(e){return c(this._pub,e)},s.prototype.getPrivateKey=function(e){return c(this._priv,e)},s.prototype.getPrime=function(e){return c(this.__prime,e)},s.prototype.getGenerator=function(e){return c(this._gen,e)},s.prototype.setGenerator=function(e,t){return t=t||"utf8",r.isBuffer(e)||(e=new r(e,t)),this._gen=new f(e),this}}).call(this,e("buffer").Buffer)},{"./generatePrime":116,"bn.js":118,buffer:9,"miller-rabin":119,randombytes:149}],116:[function(e,t,r){function i(){if(null!==S)return S;var e=1048576,t=[];t[0]=2;for(var r=1,i=3;e>i;i+=2){for(var n=Math.ceil(Math.sqrt(i)),a=0;r>a&&t[a]<=n&&i%t[a]!==0;a++);r!==a&&t[a]<=n||(t[r++]=i)}return S=t,t}function n(e){for(var t=i(),r=0;r<t.length;r++)if(0===e.modn(t[r]))return 0===e.cmpn(t[r])?!0:!1;return!0}function a(e){var t=c.mont(e);return 0===l.toRed(t).redPow(e.subn(1)).fromRed().cmpn(1)}function o(e,t){function r(e){i=-1;for(var r=new c(s(Math.ceil(e/8)));r.bitLength()>e;)r.ishrn(1);if(r.isEven()&&r.iadd(h),r.testn(1)||r.iadd(l),t.cmp(l))if(t.cmp(b))o={major:[w],minor:[l]};else{for(rem=r.mod(g);rem.cmp(v);)r.iadd(w),rem=r.mod(g);o={major:[w,p],minor:[l,m]}}else{for(;r.mod(f).cmp(y);)r.iadd(w);o={major:[f],minor:[_]}}return r}if(16>e)return new c(2===t||5===t?[140,123]:[140,39]);t=new c(t);for(var i,o,d=r(e),S=d.shrn(1);;){for(;d.bitLength()>e;)d=r(e),S=d.shrn(1);if(i++,n(S)&&n(d)&&a(S)&&a(d)&&u.test(S)&&u.test(d))return d;d.iadd(o.major[i%o.major.length]),S.iadd(o.minor[i%o.minor.length])}}var s=e("randombytes");t.exports=o,o.simpleSieve=n,o.fermatTest=a;var c=e("bn.js"),f=new c(24),d=e("miller-rabin"),u=new d,h=new c(1),l=new c(2),b=new c(5),p=new c(16),m=new c(8),g=new c(10),v=new c(3),y=(new c(7),new c(11)),w=new c(4),_=new c(12),S=null},{"bn.js":118,"miller-rabin":119,randombytes:149}],117:[function(e,t,r){t.exports={modp1:{gen:"02",prime:"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff"},modp2:{gen:"02",prime:"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff"},modp5:{gen:"02",prime:"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"},modp14:{gen:"02",prime:"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff"},modp15:{gen:"02",prime:"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff"},modp16:{gen:"02",prime:"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffff"},modp17:{gen:"02",prime:"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dcc4024ffffffffffffffff"},modp18:{gen:"02",prime:"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dbe115974a3926f12fee5e438777cb6a932df8cd8bec4d073b931ba3bc832b68d9dd300741fa7bf8afc47ed2576f6936ba424663aab639c5ae4f5683423b4742bf1c978238f16cbe39d652de3fdb8befc848ad922222e04a4037c0713eb57a81a23f0c73473fc646cea306b4bcbc8862f8385ddfa9d4b7fa2c087e879683303ed5bdd3a062b3cf5b3a278a66d2a13f83f44f82ddf310ee074ab6a364597e899a0255dc164f31cc50846851df9ab48195ded7ea1b1d510bd7ee74d73faf36bc31ecfa268359046f4eb879f924009438b481c6cd7889a002ed5ee382bc9190da6fc026e479558e4475677e9aa9e3050e2765694dfc81f56e880b96e7160c980dd98edd3dfffffffffffffffff"}}},{}],118:[function(e,t,r){t.exports=e(35)},{"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/bn.js/lib/bn.js":35}],119:[function(e,t,r){function i(e){this.rand=e||new a.Rand}var n=e("bn.js"),a=e("brorand");t.exports=i,i.create=function(e){return new i(e)},i.prototype._rand=function(e){
var t=e.bitLength(),r=this.rand.generate(Math.ceil(t/8));r[0]|=3;var i=7&t;return 0!==i&&(r[r.length-1]>>=7-i),new n(r)},i.prototype.test=function(e,t,r){var i=e.bitLength(),a=n.mont(e),o=new n(1).toRed(a);t||(t=Math.max(1,i/48|0));for(var s=e.subn(1),c=s.subn(1),f=0;!s.testn(f);f++);for(var d=e.shrn(f),u=s.toRed(a),h=!0;t>0;t--){var l=this._rand(c);r&&r(l);var b=l.toRed(a).redPow(d);if(0!==b.cmp(o)&&0!==b.cmp(u)){for(var p=1;f>p;p++){if(b=b.redSqr(),0===b.cmp(o))return!1;if(0===b.cmp(u))break}if(p===f)return!1}}return h},i.prototype.getDivisor=function(e,t){var r=e.bitLength(),i=n.mont(e),a=new n(1).toRed(i);t||(t=Math.max(1,r/48|0));for(var o=e.subn(1),s=o.subn(1),c=0;!o.testn(c);c++);for(var f=e.shrn(c),d=o.toRed(i),u=!0;t>0;t--){var h=this._rand(s),l=e.gcd(h);if(0!==l.cmpn(1))return l;var b=h.toRed(i).redPow(f);if(0!==b.cmp(a)&&0!==b.cmp(d)){for(var p=1;c>p;p++){if(b=b.redSqr(),0===b.cmp(a))return b.fromRed().subn(1).gcd(e);if(0===b.cmp(d))break}if(p===c)return b=b.redSqr(),b.fromRed().subn(1).gcd(e)}}return u}},{"bn.js":118,brorand:120}],120:[function(e,t,r){t.exports=e(49)},{"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/elliptic/node_modules/brorand/index.js":49}],121:[function(e,t,r){(function(t){function i(e,t,r,i,a,o){if("function"==typeof a&&(o=a,a=void 0),"function"!=typeof o)throw new Error("No callback provided to pbkdf2");var s=n(e,t,r,i,a);setTimeout(function(){o(void 0,s)})}function n(e,r,i,n,s){if("number"!=typeof i)throw new TypeError("Iterations not a number");if(0>i)throw new TypeError("Bad iterations");if("number"!=typeof n)throw new TypeError("Key length not a number");if(0>n||n>o)throw new TypeError("Bad key length");s=s||"sha1",t.isBuffer(e)||(e=new t(e,"binary")),t.isBuffer(r)||(r=new t(r,"binary"));var c,f=1,d=new t(n),u=new t(r.length+4);r.copy(u,0,0,r.length);for(var h,l,b=1;f>=b;b++){u.writeUInt32BE(b,r.length);var p=a(s,e).update(u).digest();c||(c=p.length,l=new t(c),f=Math.ceil(n/c),h=n-(f-1)*c),p.copy(l,0,0,c);for(var m=1;i>m;m++){p=a(s,e).update(p).digest();for(var g=0;c>g;g++)l[g]^=p[g]}var v=(b-1)*c,y=b===f?h:c;l.copy(d,v,0,y)}return d}var a=e("create-hmac"),o=Math.pow(2,30)-1;r.pbkdf2=i,r.pbkdf2Sync=n}).call(this,e("buffer").Buffer)},{buffer:9,"create-hmac":113}],122:[function(e,t,r){r.publicEncrypt=e("./publicEncrypt"),r.privateDecrypt=e("./privateDecrypt"),r.privateEncrypt=function(e,t){return r.publicEncrypt(e,t,!0)},r.publicDecrypt=function(e,t){return r.privateDecrypt(e,t,!0)}},{"./privateDecrypt":145,"./publicEncrypt":146}],123:[function(e,t,r){(function(r){function i(e){var t=new r(4);return t.writeUInt32BE(e,0),t}var n=e("create-hash");t.exports=function(e,t){for(var a,o=new r(""),s=0;o.length<t;)a=i(s++),o=r.concat([o,n("sha1").update(e).update(a).digest()]);return o.slice(0,t)}}).call(this,e("buffer").Buffer)},{buffer:9,"create-hash":101}],124:[function(e,t,r){t.exports=e(35)},{"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/bn.js/lib/bn.js":35}],125:[function(e,t,r){t.exports=e(36)},{"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/browserify-rsa/index.js":36,"bn.js":124,buffer:9,randombytes:149}],126:[function(e,t,r){t.exports=e(57)},{"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/EVP_BytesToKey.js":57,buffer:9,"create-hash":101}],127:[function(e,t,r){t.exports=e(58)},{"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/aesid.json":58}],128:[function(e,t,r){t.exports=e(59)},{"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/asn1.js":59,"asn1.js":131}],129:[function(e,t,r){t.exports=e(60)},{"./EVP_BytesToKey":126,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/fixProc.js":60,"browserify-aes":17,buffer:9}],130:[function(e,t,r){t.exports=e(61)},{"./aesid.json":127,"./asn1":128,"./fixProc":129,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/index.js":61,"browserify-aes":17,buffer:9,"pbkdf2-compat":144}],131:[function(e,t,r){t.exports=e(62)},{"./asn1/api":132,"./asn1/base":134,"./asn1/constants":138,"./asn1/decoders":140,"./asn1/encoders":142,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/node_modules/asn1.js/lib/asn1.js":62,"bn.js":124}],132:[function(e,t,r){t.exports=e(63)},{"../asn1":131,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/node_modules/asn1.js/lib/asn1/api.js":63,inherits:151,vm:167}],133:[function(e,t,r){t.exports=e(64)},{"../base":134,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/node_modules/asn1.js/lib/asn1/base/buffer.js":64,buffer:9,inherits:151}],134:[function(e,t,r){t.exports=e(65)},{"./buffer":133,"./node":135,"./reporter":136,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/node_modules/asn1.js/lib/asn1/base/index.js":65}],135:[function(e,t,r){t.exports=e(66)},{"../base":134,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/node_modules/asn1.js/lib/asn1/base/node.js":66,"minimalistic-assert":143}],136:[function(e,t,r){t.exports=e(67)},{"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/node_modules/asn1.js/lib/asn1/base/reporter.js":67,inherits:151}],137:[function(e,t,r){t.exports=e(68)},{"../constants":138,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/node_modules/asn1.js/lib/asn1/constants/der.js":68}],138:[function(e,t,r){t.exports=e(69)},{"./der":137,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/node_modules/asn1.js/lib/asn1/constants/index.js":69}],139:[function(e,t,r){t.exports=e(70)},{"../../asn1":131,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/node_modules/asn1.js/lib/asn1/decoders/der.js":70,inherits:151}],140:[function(e,t,r){t.exports=e(71)},{"./der":139,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/node_modules/asn1.js/lib/asn1/decoders/index.js":71}],141:[function(e,t,r){t.exports=e(72)},{"../../asn1":131,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/node_modules/asn1.js/lib/asn1/encoders/der.js":72,buffer:9,inherits:151}],142:[function(e,t,r){t.exports=e(73)},{"./der":141,"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/node_modules/asn1.js/lib/asn1/encoders/index.js":73}],143:[function(e,t,r){t.exports=e(74)},{"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/node_modules/asn1.js/node_modules/minimalistic-assert/index.js":74}],144:[function(e,t,r){t.exports=e(75)},{"/home/maraoz/git/bitcore-mnemonic/node_modules/bitcore-build/node_modules/browserify/node_modules/crypto-browserify/node_modules/browserify-sign/node_modules/parse-asn1/node_modules/pbkdf2-compat/browser.js":75,buffer:9,"create-hmac":113}],145:[function(e,t,r){(function(r){function i(e,t){var i=(e.modulus,e.modulus.byteLength()),n=(t.length,u("sha1").update(new r("")).digest()),o=n.length;if(0!==t[0])throw new Error("decryption error");var f=t.slice(1,o+1),d=t.slice(o+1),h=c(f,s(d,o)),l=c(d,s(h,i-o-1));if(a(n,l.slice(0,o)))throw new Error("decryption error");for(var b=o;0===l[b];)b++;if(1!==l[b++])throw new Error("decryption error");return l.slice(b)}function n(e,t,r){for(var i=t.slice(0,2),n=2,a=0;0!==t[n++];)if(n>=t.length){a++;break}{var o=t.slice(2,n-1);t.slice(n-1,n)}if(("0002"!==i.toString("hex")&&!r||"0001"!==i.toString("hex")&&r)&&a++,o.length<8&&a++,a)throw new Error("decryption error");return t.slice(n)}function a(e,t){e=new r(e),t=new r(t);var i=0,n=e.length;e.length!==t.length&&(i++,n=Math.min(e.length,t.length));for(var a=-1;++a<n;)i+=e[a]^t[a];return i}var o=e("parse-asn1"),s=e("./mgf"),c=e("./xor"),f=e("bn.js"),d=e("browserify-rsa"),u=e("create-hash"),h=e("./withPublic");t.exports=function(e,t,a){var s;s=e.padding?e.padding:a?1:4;var c=o(e),u=c.modulus.byteLength();if(t.length>u||new f(t).cmp(c.modulus)>=0)throw new Error("decryption error");var l;l=a?h(new f(t),c):d(t,c);var b=new r(u-l.length);if(b.fill(0),l=r.concat([b,l],u),4===s)return i(c,l);if(1===s)return n(c,l,a);if(3===s)return l;throw new Error("unknown padding")}}).call(this,e("buffer").Buffer)},{"./mgf":123,"./withPublic":147,"./xor":148,"bn.js":124,"browserify-rsa":125,buffer:9,"create-hash":101,"parse-asn1":130}],146:[function(e,t,r){(function(r){function i(e,t){var i=e.modulus.byteLength(),n=t.length,a=c("sha1").update(new r("")).digest(),o=a.length,h=2*o;if(n>i-h-2)throw new Error("message too long");var l=new r(i-n-h-2);l.fill(0);var b=i-o-1,p=s(o),m=d(r.concat([a,l,new r([1]),t],b),f(p,b)),g=d(p,f(m,o));return new u(r.concat([new r([0]),g,m],i))}function n(e,t,i){var n=t.length,o=e.modulus.byteLength();if(n>o-11)throw new Error("message too long");var s;return i?(s=new r(o-n-3),s.fill(255)):s=a(o-n-3),new u(r.concat([new r([0,i?1:2]),s,new r([0]),t],o))}function a(e,t){for(var i,n=new r(e),a=0,o=s(2*e),c=0;e>a;)c===o.length&&(o=s(2*e),c=0),i=o[c++],i&&(n[a++]=i);return n}var o=e("parse-asn1"),s=e("randombytes"),c=e("create-hash"),f=e("./mgf"),d=e("./xor"),u=e("bn.js"),h=e("./withPublic"),l=e("browserify-rsa");t.exports=function(e,t,r){var a;a=e.padding?e.padding:r?1:4;var s,c=o(e);if(4===a)s=i(c,t);else if(1===a)s=n(c,t,r);else{if(3!==a)throw new Error("unknown padding");if(s=new u(t),s.cmp(c.modulus)>=0)throw new Error("data too long for modulus")}return r?l(s,c):h(s,c)}}).call(this,e("buffer").Buffer)},{"./mgf":123,"./withPublic":147,"./xor":148,"bn.js":124,"browserify-rsa":125,buffer:9,"create-hash":101,"parse-asn1":130,randombytes:149}],147:[function(e,t,r){(function(r){function i(e,t){return new r(e.toRed(n.mont(t.modulus)).redPow(new n(t.publicExponent)).fromRed().toArray())}var n=e("bn.js");t.exports=i}).call(this,e("buffer").Buffer)},{"bn.js":124,buffer:9}],148:[function(e,t,r){t.exports=function(e,t){for(var r=e.length,i=-1;++i<r;)e[i]^=t[i];return e}},{}],149:[function(e,t,r){(function(e,r,i){"use strict";function n(t,r){var n=new i(t);return o.getRandomValues(n),"function"==typeof r?e.nextTick(function(){r(null,n)}):n}function a(){throw new Error("secure random number generation not supported by this browser\nuse chrome, FireFox or Internet Explorer 11")}var o=r.crypto||r.msCrypto;t.exports=o&&o.getRandomValues?n:a}).call(this,e("_process"),"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{},e("buffer").Buffer)},{_process:153,buffer:9}],150:[function(e,t,r){function i(){this._events=this._events||{},this._maxListeners=this._maxListeners||void 0}function n(e){return"function"==typeof e}function a(e){return"number"==typeof e}function o(e){return"object"==typeof e&&null!==e}function s(e){return void 0===e}t.exports=i,i.EventEmitter=i,i.prototype._events=void 0,i.prototype._maxListeners=void 0,i.defaultMaxListeners=10,i.prototype.setMaxListeners=function(e){if(!a(e)||0>e||isNaN(e))throw TypeError("n must be a positive number");return this._maxListeners=e,this},i.prototype.emit=function(e){var t,r,i,a,c,f;if(this._events||(this._events={}),"error"===e&&(!this._events.error||o(this._events.error)&&!this._events.error.length)){if(t=arguments[1],t instanceof Error)throw t;throw TypeError('Uncaught, unspecified "error" event.')}if(r=this._events[e],s(r))return!1;if(n(r))switch(arguments.length){case 1:r.call(this);break;case 2:r.call(this,arguments[1]);break;case 3:r.call(this,arguments[1],arguments[2]);break;default:for(i=arguments.length,a=new Array(i-1),c=1;i>c;c++)a[c-1]=arguments[c];r.apply(this,a)}else if(o(r)){for(i=arguments.length,a=new Array(i-1),c=1;i>c;c++)a[c-1]=arguments[c];for(f=r.slice(),i=f.length,c=0;i>c;c++)f[c].apply(this,a)}return!0},i.prototype.addListener=function(e,t){var r;if(!n(t))throw TypeError("listener must be a function");if(this._events||(this._events={}),this._events.newListener&&this.emit("newListener",e,n(t.listener)?t.listener:t),this._events[e]?o(this._events[e])?this._events[e].push(t):this._events[e]=[this._events[e],t]:this._events[e]=t,o(this._events[e])&&!this._events[e].warned){var r;r=s(this._maxListeners)?i.defaultMaxListeners:this._maxListeners,r&&r>0&&this._events[e].length>r&&(this._events[e].warned=!0,console.error("(node) warning: possible EventEmitter memory leak detected. %d listeners added. Use emitter.setMaxListeners() to increase limit.",this._events[e].length),"function"==typeof console.trace&&console.trace())}return this},i.prototype.on=i.prototype.addListener,i.prototype.once=function(e,t){function r(){this.removeListener(e,r),i||(i=!0,t.apply(this,arguments))}if(!n(t))throw TypeError("listener must be a function");var i=!1;return r.listener=t,this.on(e,r),this},i.prototype.removeListener=function(e,t){var r,i,a,s;if(!n(t))throw TypeError("listener must be a function");if(!this._events||!this._events[e])return this;if(r=this._events[e],a=r.length,i=-1,r===t||n(r.listener)&&r.listener===t)delete this._events[e],this._events.removeListener&&this.emit("removeListener",e,t);else if(o(r)){for(s=a;s-->0;)if(r[s]===t||r[s].listener&&r[s].listener===t){i=s;break}if(0>i)return this;1===r.length?(r.length=0,delete this._events[e]):r.splice(i,1),this._events.removeListener&&this.emit("removeListener",e,t)}return this},i.prototype.removeAllListeners=function(e){var t,r;if(!this._events)return this;if(!this._events.removeListener)return 0===arguments.length?this._events={}:this._events[e]&&delete this._events[e],this;if(0===arguments.length){for(t in this._events)"removeListener"!==t&&this.removeAllListeners(t);return this.removeAllListeners("removeListener"),this._events={},this}if(r=this._events[e],n(r))this.removeListener(e,r);else for(;r.length;)this.removeListener(e,r[r.length-1]);return delete this._events[e],this},i.prototype.listeners=function(e){var t;return t=this._events&&this._events[e]?n(this._events[e])?[this._events[e]]:this._events[e].slice():[]},i.listenerCount=function(e,t){var r;return r=e._events&&e._events[t]?n(e._events[t])?1:e._events[t].length:0}},{}],151:[function(e,t,r){t.exports="function"==typeof Object.create?function(e,t){e.super_=t,e.prototype=Object.create(t.prototype,{constructor:{value:e,enumerable:!1,writable:!0,configurable:!0}})}:function(e,t){e.super_=t;var r=function(){};r.prototype=t.prototype,e.prototype=new r,e.prototype.constructor=e}},{}],152:[function(e,t,r){t.exports=Array.isArray||function(e){return"[object Array]"==Object.prototype.toString.call(e)}},{}],153:[function(e,t,r){function i(){}var n=t.exports={};n.nextTick=function(){var e="undefined"!=typeof window&&window.setImmediate,t="undefined"!=typeof window&&window.MutationObserver,r="undefined"!=typeof window&&window.postMessage&&window.addEventListener;if(e)return function(e){return window.setImmediate(e)};var i=[];if(t){var n=document.createElement("div"),a=new MutationObserver(function(){var e=i.slice();i.length=0,e.forEach(function(e){e()})});return a.observe(n,{attributes:!0}),function(e){i.length||n.setAttribute("yes","no"),i.push(e)}}return r?(window.addEventListener("message",function(e){var t=e.source;if((t===window||null===t)&&"process-tick"===e.data&&(e.stopPropagation(),i.length>0)){var r=i.shift();r()}},!0),function(e){i.push(e),window.postMessage("process-tick","*")}):function(e){setTimeout(e,0)}}(),n.title="browser",n.browser=!0,n.env={},n.argv=[],n.on=i,n.addListener=i,n.once=i,n.off=i,n.removeListener=i,n.removeAllListeners=i,n.emit=i,n.binding=function(e){throw new Error("process.binding is not supported")},n.cwd=function(){return"/"},n.chdir=function(e){throw new Error("process.chdir is not supported")}},{}],154:[function(e,t,r){t.exports=e("./lib/_stream_duplex.js")},{"./lib/_stream_duplex.js":155}],155:[function(e,t,r){(function(r){function i(e){return this instanceof i?(c.call(this,e),f.call(this,e),e&&e.readable===!1&&(this.readable=!1),e&&e.writable===!1&&(this.writable=!1),this.allowHalfOpen=!0,e&&e.allowHalfOpen===!1&&(this.allowHalfOpen=!1),void this.once("end",n)):new i(e)}function n(){this.allowHalfOpen||this._writableState.ended||r.nextTick(this.end.bind(this))}function a(e,t){for(var r=0,i=e.length;i>r;r++)t(e[r],r)}t.exports=i;var o=Object.keys||function(e){var t=[];for(var r in e)t.push(r);return t},s=e("core-util-is");s.inherits=e("inherits");var c=e("./_stream_readable"),f=e("./_stream_writable");s.inherits(i,c),a(o(f.prototype),function(e){i.prototype[e]||(i.prototype[e]=f.prototype[e])})}).call(this,e("_process"))},{"./_stream_readable":157,"./_stream_writable":159,_process:153,"core-util-is":160,inherits:151}],156:[function(e,t,r){function i(e){return this instanceof i?void n.call(this,e):new i(e)}t.exports=i;var n=e("./_stream_transform"),a=e("core-util-is");a.inherits=e("inherits"),a.inherits(i,n),i.prototype._transform=function(e,t,r){r(null,e)}},{"./_stream_transform":158,"core-util-is":160,inherits:151}],157:[function(e,t,r){(function(r){function i(t,r){t=t||{};var i=t.highWaterMark;this.highWaterMark=i||0===i?i:16384,this.highWaterMark=~~this.highWaterMark,this.buffer=[],this.length=0,this.pipes=null,this.pipesCount=0,this.flowing=!1,this.ended=!1,this.endEmitted=!1,this.reading=!1,this.calledRead=!1,this.sync=!0,this.needReadable=!1,this.emittedReadable=!1,this.readableListening=!1,this.objectMode=!!t.objectMode,this.defaultEncoding=t.defaultEncoding||"utf8",this.ranOut=!1,this.awaitDrain=0,this.readingMore=!1,this.decoder=null,this.encoding=null,t.encoding&&(I||(I=e("string_decoder/").StringDecoder),this.decoder=new I(t.encoding),this.encoding=t.encoding)}function n(e){return this instanceof n?(this._readableState=new i(e,this),this.readable=!0,void j.call(this)):new n(e)}function a(e,t,r,i,n){var a=f(t,r);if(a)e.emit("error",a);else if(null===r||void 0===r)t.reading=!1,t.ended||d(e,t);else if(t.objectMode||r&&r.length>0)if(t.ended&&!n){var s=new Error("stream.push() after EOF");e.emit("error",s)}else if(t.endEmitted&&n){var s=new Error("stream.unshift() after end event");e.emit("error",s)}else!t.decoder||n||i||(r=t.decoder.write(r)),t.length+=t.objectMode?1:r.length,n?t.buffer.unshift(r):(t.reading=!1,t.buffer.push(r)),t.needReadable&&u(e),l(e,t);else n||(t.reading=!1);return o(t)}function o(e){return!e.ended&&(e.needReadable||e.length<e.highWaterMark||0===e.length)}function s(e){if(e>=B)e=B;else{e--;for(var t=1;32>t;t<<=1)e|=e>>t;e++}return e}function c(e,t){return 0===t.length&&t.ended?0:t.objectMode?0===e?0:1:null===e||isNaN(e)?t.flowing&&t.buffer.length?t.buffer[0].length:t.length:0>=e?0:(e>t.highWaterMark&&(t.highWaterMark=s(e)),e>t.length?t.ended?t.length:(t.needReadable=!0,0):e)}function f(e,t){var r=null;return E.isBuffer(t)||"string"==typeof t||null===t||void 0===t||e.objectMode||(r=new TypeError("Invalid non-string/buffer chunk")),r}function d(e,t){if(t.decoder&&!t.ended){var r=t.decoder.end();r&&r.length&&(t.buffer.push(r),t.length+=t.objectMode?1:r.length)}t.ended=!0,t.length>0?u(e):w(e)}function u(e){var t=e._readableState;t.needReadable=!1,t.emittedReadable||(t.emittedReadable=!0,t.sync?r.nextTick(function(){h(e)}):h(e))}function h(e){e.emit("readable")}function l(e,t){t.readingMore||(t.readingMore=!0,r.nextTick(function(){b(e,t)}))}function b(e,t){for(var r=t.length;!t.reading&&!t.flowing&&!t.ended&&t.length<t.highWaterMark&&(e.read(0),r!==t.length);)r=t.length;t.readingMore=!1}function p(e){return function(){var t=e._readableState;t.awaitDrain--,0===t.awaitDrain&&m(e)}}function m(e){function t(e,t,n){var a=e.write(r);!1===a&&i.awaitDrain++}var r,i=e._readableState;for(i.awaitDrain=0;i.pipesCount&&null!==(r=e.read());)if(1===i.pipesCount?t(i.pipes,0,null):_(i.pipes,t),e.emit("data",r),i.awaitDrain>0)return;return 0===i.pipesCount?(i.flowing=!1,void(x.listenerCount(e,"data")>0&&v(e))):void(i.ranOut=!0)}function g(){this._readableState.ranOut&&(this._readableState.ranOut=!1,m(this))}function v(e,t){var i=e._readableState;if(i.flowing)throw new Error("Cannot switch to old mode now.");var n=t||!1,a=!1;e.readable=!0,e.pipe=j.prototype.pipe,e.on=e.addListener=j.prototype.on,e.on("readable",function(){a=!0;for(var t;!n&&null!==(t=e.read());)e.emit("data",t);null===t&&(a=!1,e._readableState.needReadable=!0)}),e.pause=function(){n=!0,this.emit("pause")},e.resume=function(){n=!1,a?r.nextTick(function(){e.emit("readable")}):this.read(0),this.emit("resume")},e.emit("readable")}function y(e,t){var r,i=t.buffer,n=t.length,a=!!t.decoder,o=!!t.objectMode;if(0===i.length)return null;if(0===n)r=null;else if(o)r=i.shift();else if(!e||e>=n)r=a?i.join(""):E.concat(i,n),i.length=0;else if(e<i[0].length){var s=i[0];r=s.slice(0,e),i[0]=s.slice(e)}else if(e===i[0].length)r=i.shift();else{r=a?"":new E(e);for(var c=0,f=0,d=i.length;d>f&&e>c;f++){var s=i[0],u=Math.min(e-c,s.length);a?r+=s.slice(0,u):s.copy(r,c,0,u),u<s.length?i[0]=s.slice(u):i.shift(),c+=u}}return r}function w(e){var t=e._readableState;if(t.length>0)throw new Error("endReadable called on non-empty stream");!t.endEmitted&&t.calledRead&&(t.ended=!0,r.nextTick(function(){t.endEmitted||0!==t.length||(t.endEmitted=!0,e.readable=!1,e.emit("end"))}))}function _(e,t){for(var r=0,i=e.length;i>r;r++)t(e[r],r)}function S(e,t){for(var r=0,i=e.length;i>r;r++)if(e[r]===t)return r;return-1}t.exports=n;var k=e("isarray"),E=e("buffer").Buffer;n.ReadableState=i;var x=e("events").EventEmitter;x.listenerCount||(x.listenerCount=function(e,t){return e.listeners(t).length});var j=e("stream"),A=e("core-util-is");A.inherits=e("inherits");var I;A.inherits(n,j),n.prototype.push=function(e,t){var r=this._readableState;return"string"!=typeof e||r.objectMode||(t=t||r.defaultEncoding,t!==r.encoding&&(e=new E(e,t),t="")),a(this,r,e,t,!1)},n.prototype.unshift=function(e){var t=this._readableState;return a(this,t,e,"",!0)},n.prototype.setEncoding=function(t){I||(I=e("string_decoder/").StringDecoder),this._readableState.decoder=new I(t),this._readableState.encoding=t};var B=8388608;n.prototype.read=function(e){var t=this._readableState;t.calledRead=!0;var r,i=e;if(("number"!=typeof e||e>0)&&(t.emittedReadable=!1),0===e&&t.needReadable&&(t.length>=t.highWaterMark||t.ended))return u(this),null;if(e=c(e,t),0===e&&t.ended)return r=null,t.length>0&&t.decoder&&(r=y(e,t),t.length-=r.length),0===t.length&&w(this),r;var n=t.needReadable;return t.length-e<=t.highWaterMark&&(n=!0),(t.ended||t.reading)&&(n=!1),n&&(t.reading=!0,t.sync=!0,0===t.length&&(t.needReadable=!0),this._read(t.highWaterMark),t.sync=!1),n&&!t.reading&&(e=c(i,t)),r=e>0?y(e,t):null,null===r&&(t.needReadable=!0,e=0),t.length-=e,0!==t.length||t.ended||(t.needReadable=!0),t.ended&&!t.endEmitted&&0===t.length&&w(this),r},n.prototype._read=function(e){this.emit("error",new Error("not implemented"))},n.prototype.pipe=function(e,t){function i(e){e===d&&a()}function n(){e.end()}function a(){e.removeListener("close",s),e.removeListener("finish",c),e.removeListener("drain",b),e.removeListener("error",o),e.removeListener("unpipe",i),d.removeListener("end",n),d.removeListener("end",a),(!e._writableState||e._writableState.needDrain)&&b()}function o(t){f(),e.removeListener("error",o),0===x.listenerCount(e,"error")&&e.emit("error",t)}function s(){e.removeListener("finish",c),f()}function c(){e.removeListener("close",s),f()}function f(){d.unpipe(e)}var d=this,u=this._readableState;switch(u.pipesCount){case 0:u.pipes=e;break;case 1:u.pipes=[u.pipes,e];break;default:u.pipes.push(e)}u.pipesCount+=1;var h=(!t||t.end!==!1)&&e!==r.stdout&&e!==r.stderr,l=h?n:a;u.endEmitted?r.nextTick(l):d.once("end",l),e.on("unpipe",i);var b=p(d);return e.on("drain",b),e._events&&e._events.error?k(e._events.error)?e._events.error.unshift(o):e._events.error=[o,e._events.error]:e.on("error",o),e.once("close",s),e.once("finish",c),e.emit("pipe",d),u.flowing||(this.on("readable",g),u.flowing=!0,r.nextTick(function(){m(d)})),e},n.prototype.unpipe=function(e){var t=this._readableState;if(0===t.pipesCount)return this;if(1===t.pipesCount)return e&&e!==t.pipes?this:(e||(e=t.pipes),t.pipes=null,t.pipesCount=0,this.removeListener("readable",g),t.flowing=!1,e&&e.emit("unpipe",this),this);if(!e){var r=t.pipes,i=t.pipesCount;t.pipes=null,t.pipesCount=0,this.removeListener("readable",g),t.flowing=!1;for(var n=0;i>n;n++)r[n].emit("unpipe",this);return this}var n=S(t.pipes,e);return-1===n?this:(t.pipes.splice(n,1),t.pipesCount-=1,1===t.pipesCount&&(t.pipes=t.pipes[0]),e.emit("unpipe",this),this)},n.prototype.on=function(e,t){var r=j.prototype.on.call(this,e,t);if("data"!==e||this._readableState.flowing||v(this),"readable"===e&&this.readable){var i=this._readableState;i.readableListening||(i.readableListening=!0,i.emittedReadable=!1,i.needReadable=!0,i.reading?i.length&&u(this,i):this.read(0))}return r},n.prototype.addListener=n.prototype.on,n.prototype.resume=function(){v(this),this.read(0),this.emit("resume")},n.prototype.pause=function(){v(this,!0),this.emit("pause")},n.prototype.wrap=function(e){var t=this._readableState,r=!1,i=this;e.on("end",function(){if(t.decoder&&!t.ended){var e=t.decoder.end();e&&e.length&&i.push(e)}i.push(null)}),e.on("data",function(n){if(t.decoder&&(n=t.decoder.write(n)),(!t.objectMode||null!==n&&void 0!==n)&&(t.objectMode||n&&n.length)){var a=i.push(n);a||(r=!0,e.pause())}});for(var n in e)"function"==typeof e[n]&&"undefined"==typeof this[n]&&(this[n]=function(t){return function(){return e[t].apply(e,arguments)}}(n));var a=["error","close","destroy","pause","resume"];return _(a,function(t){e.on(t,i.emit.bind(i,t))}),i._read=function(t){r&&(r=!1,e.resume())},i},n._fromList=y}).call(this,e("_process"))},{_process:153,buffer:9,"core-util-is":160,events:150,inherits:151,isarray:152,stream:165,"string_decoder/":166}],158:[function(e,t,r){function i(e,t){this.afterTransform=function(e,r){return n(t,e,r)},this.needTransform=!1,this.transforming=!1,this.writecb=null,this.writechunk=null}function n(e,t,r){var i=e._transformState;i.transforming=!1;var n=i.writecb;if(!n)return e.emit("error",new Error("no writecb in Transform class"));i.writechunk=null,i.writecb=null,null!==r&&void 0!==r&&e.push(r),n&&n(t);var a=e._readableState;a.reading=!1,(a.needReadable||a.length<a.highWaterMark)&&e._read(a.highWaterMark)}function a(e){if(!(this instanceof a))return new a(e);s.call(this,e);var t=(this._transformState=new i(e,this),this);this._readableState.needReadable=!0,this._readableState.sync=!1,this.once("finish",function(){"function"==typeof this._flush?this._flush(function(e){o(t,e)}):o(t)})}function o(e,t){if(t)return e.emit("error",t);var r=e._writableState,i=(e._readableState,e._transformState);if(r.length)throw new Error("calling transform done when ws.length != 0");if(i.transforming)throw new Error("calling transform done when still transforming");return e.push(null)}t.exports=a;var s=e("./_stream_duplex"),c=e("core-util-is");c.inherits=e("inherits"),c.inherits(a,s),a.prototype.push=function(e,t){return this._transformState.needTransform=!1,s.prototype.push.call(this,e,t)},a.prototype._transform=function(e,t,r){throw new Error("not implemented")},a.prototype._write=function(e,t,r){var i=this._transformState;if(i.writecb=r,i.writechunk=e,i.writeencoding=t,!i.transforming){var n=this._readableState;(i.needTransform||n.needReadable||n.length<n.highWaterMark)&&this._read(n.highWaterMark)}},a.prototype._read=function(e){var t=this._transformState;null!==t.writechunk&&t.writecb&&!t.transforming?(t.transforming=!0,this._transform(t.writechunk,t.writeencoding,t.afterTransform)):t.needTransform=!0}},{"./_stream_duplex":155,"core-util-is":160,inherits:151}],159:[function(e,t,r){(function(r){function i(e,t,r){this.chunk=e,this.encoding=t,this.callback=r}function n(e,t){e=e||{};var r=e.highWaterMark;this.highWaterMark=r||0===r?r:16384,this.objectMode=!!e.objectMode,this.highWaterMark=~~this.highWaterMark,this.needDrain=!1,this.ending=!1,this.ended=!1,this.finished=!1;var i=e.decodeStrings===!1;this.decodeStrings=!i,this.defaultEncoding=e.defaultEncoding||"utf8",this.length=0,this.writing=!1,this.sync=!0,this.bufferProcessing=!1,this.onwrite=function(e){l(t,e)},this.writecb=null,this.writelen=0,this.buffer=[],this.errorEmitted=!1}function a(t){var r=e("./_stream_duplex");return this instanceof a||this instanceof r?(this._writableState=new n(t,this),this.writable=!0,void S.call(this)):new a(t)}function o(e,t,i){var n=new Error("write after end");e.emit("error",n),r.nextTick(function(){i(n)})}function s(e,t,i,n){var a=!0;if(!w.isBuffer(i)&&"string"!=typeof i&&null!==i&&void 0!==i&&!t.objectMode){var o=new TypeError("Invalid non-string/buffer chunk");e.emit("error",o),r.nextTick(function(){n(o)}),a=!1}return a}function c(e,t,r){return e.objectMode||e.decodeStrings===!1||"string"!=typeof t||(t=new w(t,r)),t}function f(e,t,r,n,a){r=c(t,r,n),w.isBuffer(r)&&(n="buffer");var o=t.objectMode?1:r.length;t.length+=o;var s=t.length<t.highWaterMark;return s||(t.needDrain=!0),t.writing?t.buffer.push(new i(r,n,a)):d(e,t,o,r,n,a),s}function d(e,t,r,i,n,a){t.writelen=r,t.writecb=a,t.writing=!0,t.sync=!0,e._write(i,n,t.onwrite),t.sync=!1}function u(e,t,i,n,a){i?r.nextTick(function(){a(n)}):a(n),e._writableState.errorEmitted=!0,e.emit("error",n)}function h(e){e.writing=!1,e.writecb=null,e.length-=e.writelen,e.writelen=0}function l(e,t){var i=e._writableState,n=i.sync,a=i.writecb;if(h(i),t)u(e,i,n,t,a);else{var o=g(e,i);o||i.bufferProcessing||!i.buffer.length||m(e,i),n?r.nextTick(function(){b(e,i,o,a)}):b(e,i,o,a)}}function b(e,t,r,i){r||p(e,t),i(),r&&v(e,t)}function p(e,t){0===t.length&&t.needDrain&&(t.needDrain=!1,e.emit("drain"))}function m(e,t){t.bufferProcessing=!0;for(var r=0;r<t.buffer.length;r++){var i=t.buffer[r],n=i.chunk,a=i.encoding,o=i.callback,s=t.objectMode?1:n.length;if(d(e,t,s,n,a,o),t.writing){r++;break}}t.bufferProcessing=!1,r<t.buffer.length?t.buffer=t.buffer.slice(r):t.buffer.length=0}function g(e,t){return t.ending&&0===t.length&&!t.finished&&!t.writing}function v(e,t){var r=g(e,t);return r&&(t.finished=!0,e.emit("finish")),r}function y(e,t,i){t.ending=!0,v(e,t),i&&(t.finished?r.nextTick(i):e.once("finish",i)),t.ended=!0}t.exports=a;var w=e("buffer").Buffer;a.WritableState=n;var _=e("core-util-is");_.inherits=e("inherits");

var S=e("stream");_.inherits(a,S),a.prototype.pipe=function(){this.emit("error",new Error("Cannot pipe. Not readable."))},a.prototype.write=function(e,t,r){var i=this._writableState,n=!1;return"function"==typeof t&&(r=t,t=null),w.isBuffer(e)?t="buffer":t||(t=i.defaultEncoding),"function"!=typeof r&&(r=function(){}),i.ended?o(this,i,r):s(this,i,e,r)&&(n=f(this,i,e,t,r)),n},a.prototype._write=function(e,t,r){r(new Error("not implemented"))},a.prototype.end=function(e,t,r){var i=this._writableState;"function"==typeof e?(r=e,e=null,t=null):"function"==typeof t&&(r=t,t=null),"undefined"!=typeof e&&null!==e&&this.write(e,t),i.ending||i.finished||y(this,i,r)}}).call(this,e("_process"))},{"./_stream_duplex":155,_process:153,buffer:9,"core-util-is":160,inherits:151,stream:165}],160:[function(e,t,r){(function(e){function t(e){return Array.isArray(e)}function i(e){return"boolean"==typeof e}function n(e){return null===e}function a(e){return null==e}function o(e){return"number"==typeof e}function s(e){return"string"==typeof e}function c(e){return"symbol"==typeof e}function f(e){return void 0===e}function d(e){return u(e)&&"[object RegExp]"===g(e)}function u(e){return"object"==typeof e&&null!==e}function h(e){return u(e)&&"[object Date]"===g(e)}function l(e){return u(e)&&("[object Error]"===g(e)||e instanceof Error)}function b(e){return"function"==typeof e}function p(e){return null===e||"boolean"==typeof e||"number"==typeof e||"string"==typeof e||"symbol"==typeof e||"undefined"==typeof e}function m(t){return e.isBuffer(t)}function g(e){return Object.prototype.toString.call(e)}r.isArray=t,r.isBoolean=i,r.isNull=n,r.isNullOrUndefined=a,r.isNumber=o,r.isString=s,r.isSymbol=c,r.isUndefined=f,r.isRegExp=d,r.isObject=u,r.isDate=h,r.isError=l,r.isFunction=b,r.isPrimitive=p,r.isBuffer=m}).call(this,e("buffer").Buffer)},{buffer:9}],161:[function(e,t,r){t.exports=e("./lib/_stream_passthrough.js")},{"./lib/_stream_passthrough.js":156}],162:[function(e,t,r){var i=e("stream");r=t.exports=e("./lib/_stream_readable.js"),r.Stream=i,r.Readable=r,r.Writable=e("./lib/_stream_writable.js"),r.Duplex=e("./lib/_stream_duplex.js"),r.Transform=e("./lib/_stream_transform.js"),r.PassThrough=e("./lib/_stream_passthrough.js")},{"./lib/_stream_duplex.js":155,"./lib/_stream_passthrough.js":156,"./lib/_stream_readable.js":157,"./lib/_stream_transform.js":158,"./lib/_stream_writable.js":159,stream:165}],163:[function(e,t,r){t.exports=e("./lib/_stream_transform.js")},{"./lib/_stream_transform.js":158}],164:[function(e,t,r){t.exports=e("./lib/_stream_writable.js")},{"./lib/_stream_writable.js":159}],165:[function(e,t,r){function i(){n.call(this)}t.exports=i;var n=e("events").EventEmitter,a=e("inherits");a(i,n),i.Readable=e("readable-stream/readable.js"),i.Writable=e("readable-stream/writable.js"),i.Duplex=e("readable-stream/duplex.js"),i.Transform=e("readable-stream/transform.js"),i.PassThrough=e("readable-stream/passthrough.js"),i.Stream=i,i.prototype.pipe=function(e,t){function r(t){e.writable&&!1===e.write(t)&&f.pause&&f.pause()}function i(){f.readable&&f.resume&&f.resume()}function a(){d||(d=!0,e.end())}function o(){d||(d=!0,"function"==typeof e.destroy&&e.destroy())}function s(e){if(c(),0===n.listenerCount(this,"error"))throw e}function c(){f.removeListener("data",r),e.removeListener("drain",i),f.removeListener("end",a),f.removeListener("close",o),f.removeListener("error",s),e.removeListener("error",s),f.removeListener("end",c),f.removeListener("close",c),e.removeListener("close",c)}var f=this;f.on("data",r),e.on("drain",i),e._isStdio||t&&t.end===!1||(f.on("end",a),f.on("close",o));var d=!1;return f.on("error",s),e.on("error",s),f.on("end",c),f.on("close",c),e.on("close",c),e.emit("pipe",f),e}},{events:150,inherits:151,"readable-stream/duplex.js":154,"readable-stream/passthrough.js":161,"readable-stream/readable.js":162,"readable-stream/transform.js":163,"readable-stream/writable.js":164}],166:[function(e,t,r){function i(e){if(e&&!c(e))throw new Error("Unknown encoding: "+e)}function n(e){return e.toString(this.encoding)}function a(e){this.charReceived=e.length%2,this.charLength=this.charReceived?2:0}function o(e){this.charReceived=e.length%3,this.charLength=this.charReceived?3:0}var s=e("buffer").Buffer,c=s.isEncoding||function(e){switch(e&&e.toLowerCase()){case"hex":case"utf8":case"utf-8":case"ascii":case"binary":case"base64":case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":case"raw":return!0;default:return!1}},f=r.StringDecoder=function(e){switch(this.encoding=(e||"utf8").toLowerCase().replace(/[-_]/,""),i(e),this.encoding){case"utf8":this.surrogateSize=3;break;case"ucs2":case"utf16le":this.surrogateSize=2,this.detectIncompleteChar=a;break;case"base64":this.surrogateSize=3,this.detectIncompleteChar=o;break;default:return void(this.write=n)}this.charBuffer=new s(6),this.charReceived=0,this.charLength=0};f.prototype.write=function(e){for(var t="";this.charLength;){var r=e.length>=this.charLength-this.charReceived?this.charLength-this.charReceived:e.length;if(e.copy(this.charBuffer,this.charReceived,0,r),this.charReceived+=r,this.charReceived<this.charLength)return"";e=e.slice(r,e.length),t=this.charBuffer.slice(0,this.charLength).toString(this.encoding);var i=t.charCodeAt(t.length-1);if(!(i>=55296&&56319>=i)){if(this.charReceived=this.charLength=0,0===e.length)return t;break}this.charLength+=this.surrogateSize,t=""}this.detectIncompleteChar(e);var n=e.length;this.charLength&&(e.copy(this.charBuffer,0,e.length-this.charReceived,n),n-=this.charReceived),t+=e.toString(this.encoding,0,n);var n=t.length-1,i=t.charCodeAt(n);if(i>=55296&&56319>=i){var a=this.surrogateSize;return this.charLength+=a,this.charReceived+=a,this.charBuffer.copy(this.charBuffer,a,0,a),e.copy(this.charBuffer,0,0,a),t.substring(0,n)}return t},f.prototype.detectIncompleteChar=function(e){for(var t=e.length>=3?3:e.length;t>0;t--){var r=e[e.length-t];if(1==t&&r>>5==6){this.charLength=2;break}if(2>=t&&r>>4==14){this.charLength=3;break}if(3>=t&&r>>3==30){this.charLength=4;break}}this.charReceived=t},f.prototype.end=function(e){var t="";if(e&&e.length&&(t=this.write(e)),this.charReceived){var r=this.charReceived,i=this.charBuffer,n=this.encoding;t+=i.slice(0,r).toString(n)}return t}},{buffer:9}],167:[function(require,module,exports){function Context(){}var indexOf=require("indexof"),Object_keys=function(e){if(Object.keys)return Object.keys(e);var t=[];for(var r in e)t.push(r);return t},forEach=function(e,t){if(e.forEach)return e.forEach(t);for(var r=0;r<e.length;r++)t(e[r],r,e)},defineProp=function(){try{return Object.defineProperty({},"_",{}),function(e,t,r){Object.defineProperty(e,t,{writable:!0,enumerable:!1,configurable:!0,value:r})}}catch(e){return function(e,t,r){e[t]=r}}}(),globals=["Array","Boolean","Date","Error","EvalError","Function","Infinity","JSON","Math","NaN","Number","Object","RangeError","ReferenceError","RegExp","String","SyntaxError","TypeError","URIError","decodeURI","decodeURIComponent","encodeURI","encodeURIComponent","escape","eval","isFinite","isNaN","parseFloat","parseInt","undefined","unescape"];Context.prototype={};var Script=exports.Script=function(e){return this instanceof Script?void(this.code=e):new Script(e)};Script.prototype.runInContext=function(e){if(!(e instanceof Context))throw new TypeError("needs a 'context' argument.");var t=document.createElement("iframe");t.style||(t.style={}),t.style.display="none",document.body.appendChild(t);var r=t.contentWindow,i=r.eval,n=r.execScript;!i&&n&&(n.call(r,"null"),i=r.eval),forEach(Object_keys(e),function(t){r[t]=e[t]}),forEach(globals,function(t){e[t]&&(r[t]=e[t])});var a=Object_keys(r),o=i.call(r,this.code);return forEach(Object_keys(r),function(t){(t in e||-1===indexOf(a,t))&&(e[t]=r[t])}),forEach(globals,function(t){t in e||defineProp(e,t,r[t])}),document.body.removeChild(t),o},Script.prototype.runInThisContext=function(){return eval(this.code)},Script.prototype.runInNewContext=function(e){var t=Script.createContext(e),r=this.runInContext(t);return forEach(Object_keys(t),function(r){e[r]=t[r]}),r},forEach(Object_keys(Script.prototype),function(e){exports[e]=Script[e]=function(t){var r=Script(t);return r[e].apply(r,[].slice.call(arguments,1))}}),exports.createScript=function(e){return exports.Script(e)},exports.createContext=Script.createContext=function(e){var t=new Context;return"object"==typeof e&&forEach(Object_keys(e),function(r){t[r]=e[r]}),t}},{indexof:168}],168:[function(e,t,r){var i=[].indexOf;t.exports=function(e,t){if(i)return e.indexOf(t);for(var r=0;r<e.length;++r)if(e[r]===t)return r;return-1}},{}],"bitcore-mnemonic":[function(e,t,r){t.exports=e("./lib/mnemonic")},{"./lib/mnemonic":2}]},{},[]);
/*!
 * jQuery JavaScript Library v1.11.3
 * http://jquery.com/
 *
 * Includes Sizzle.js
 * http://sizzlejs.com/
 *
 * Copyright 2005, 2014 jQuery Foundation, Inc. and other contributors
 * Released under the MIT license
 * http://jquery.org/license
 *
 * Date: 2015-04-28T16:19Z
 */

(function( global, factory ) {

	if ( typeof module === "object" && typeof module.exports === "object" ) {
		// For CommonJS and CommonJS-like environments where a proper window is present,
		// execute the factory and get jQuery
		// For environments that do not inherently posses a window with a document
		// (such as Node.js), expose a jQuery-making factory as module.exports
		// This accentuates the need for the creation of a real window
		// e.g. var jQuery = require("jquery")(window);
		// See ticket #14549 for more info
		module.exports = global.document ?
			factory( global, true ) :
			function( w ) {
				if ( !w.document ) {
					throw new Error( "jQuery requires a window with a document" );
				}
				return factory( w );
			};
	} else {
		factory( global );
	}

// Pass this if window is not defined yet
}(typeof window !== "undefined" ? window : this, function( window, noGlobal ) {

// Can't do this because several apps including ASP.NET trace
// the stack via arguments.caller.callee and Firefox dies if
// you try to trace through "use strict" call chains. (#13335)
// Support: Firefox 18+
//

var deletedIds = [];

var slice = deletedIds.slice;

var concat = deletedIds.concat;

var push = deletedIds.push;

var indexOf = deletedIds.indexOf;

var class2type = {};

var toString = class2type.toString;

var hasOwn = class2type.hasOwnProperty;

var support = {};



var
	version = "1.11.3",

	// Define a local copy of jQuery
	jQuery = function( selector, context ) {
		// The jQuery object is actually just the init constructor 'enhanced'
		// Need init if jQuery is called (just allow error to be thrown if not included)
		return new jQuery.fn.init( selector, context );
	},

	// Support: Android<4.1, IE<9
	// Make sure we trim BOM and NBSP
	rtrim = /^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g,

	// Matches dashed string for camelizing
	rmsPrefix = /^-ms-/,
	rdashAlpha = /-([\da-z])/gi,

	// Used by jQuery.camelCase as callback to replace()
	fcamelCase = function( all, letter ) {
		return letter.toUpperCase();
	};

jQuery.fn = jQuery.prototype = {
	// The current version of jQuery being used
	jquery: version,

	constructor: jQuery,

	// Start with an empty selector
	selector: "",

	// The default length of a jQuery object is 0
	length: 0,

	toArray: function() {
		return slice.call( this );
	},

	// Get the Nth element in the matched element set OR
	// Get the whole matched element set as a clean array
	get: function( num ) {
		return num != null ?

			// Return just the one element from the set
			( num < 0 ? this[ num + this.length ] : this[ num ] ) :

			// Return all the elements in a clean array
			slice.call( this );
	},

	// Take an array of elements and push it onto the stack
	// (returning the new matched element set)
	pushStack: function( elems ) {

		// Build a new jQuery matched element set
		var ret = jQuery.merge( this.constructor(), elems );

		// Add the old object onto the stack (as a reference)
		ret.prevObject = this;
		ret.context = this.context;

		// Return the newly-formed element set
		return ret;
	},

	// Execute a callback for every element in the matched set.
	// (You can seed the arguments with an array of args, but this is
	// only used internally.)
	each: function( callback, args ) {
		return jQuery.each( this, callback, args );
	},

	map: function( callback ) {
		return this.pushStack( jQuery.map(this, function( elem, i ) {
			return callback.call( elem, i, elem );
		}));
	},

	slice: function() {
		return this.pushStack( slice.apply( this, arguments ) );
	},

	first: function() {
		return this.eq( 0 );
	},

	last: function() {
		return this.eq( -1 );
	},

	eq: function( i ) {
		var len = this.length,
			j = +i + ( i < 0 ? len : 0 );
		return this.pushStack( j >= 0 && j < len ? [ this[j] ] : [] );
	},

	end: function() {
		return this.prevObject || this.constructor(null);
	},

	// For internal use only.
	// Behaves like an Array's method, not like a jQuery method.
	push: push,
	sort: deletedIds.sort,
	splice: deletedIds.splice
};

jQuery.extend = jQuery.fn.extend = function() {
	var src, copyIsArray, copy, name, options, clone,
		target = arguments[0] || {},
		i = 1,
		length = arguments.length,
		deep = false;

	// Handle a deep copy situation
	if ( typeof target === "boolean" ) {
		deep = target;

		// skip the boolean and the target
		target = arguments[ i ] || {};
		i++;
	}

	// Handle case when target is a string or something (possible in deep copy)
	if ( typeof target !== "object" && !jQuery.isFunction(target) ) {
		target = {};
	}

	// extend jQuery itself if only one argument is passed
	if ( i === length ) {
		target = this;
		i--;
	}

	for ( ; i < length; i++ ) {
		// Only deal with non-null/undefined values
		if ( (options = arguments[ i ]) != null ) {
			// Extend the base object
			for ( name in options ) {
				src = target[ name ];
				copy = options[ name ];

				// Prevent never-ending loop
				if ( target === copy ) {
					continue;
				}

				// Recurse if we're merging plain objects or arrays
				if ( deep && copy && ( jQuery.isPlainObject(copy) || (copyIsArray = jQuery.isArray(copy)) ) ) {
					if ( copyIsArray ) {
						copyIsArray = false;
						clone = src && jQuery.isArray(src) ? src : [];

					} else {
						clone = src && jQuery.isPlainObject(src) ? src : {};
					}

					// Never move original objects, clone them
					target[ name ] = jQuery.extend( deep, clone, copy );

				// Don't bring in undefined values
				} else if ( copy !== undefined ) {
					target[ name ] = copy;
				}
			}
		}
	}

	// Return the modified object
	return target;
};

jQuery.extend({
	// Unique for each copy of jQuery on the page
	expando: "jQuery" + ( version + Math.random() ).replace( /\D/g, "" ),

	// Assume jQuery is ready without the ready module
	isReady: true,

	error: function( msg ) {
		throw new Error( msg );
	},

	noop: function() {},

	// See test/unit/core.js for details concerning isFunction.
	// Since version 1.3, DOM methods and functions like alert
	// aren't supported. They return false on IE (#2968).
	isFunction: function( obj ) {
		return jQuery.type(obj) === "function";
	},

	isArray: Array.isArray || function( obj ) {
		return jQuery.type(obj) === "array";
	},

	isWindow: function( obj ) {
		/* jshint eqeqeq: false */
		return obj != null && obj == obj.window;
	},

	isNumeric: function( obj ) {
		// parseFloat NaNs numeric-cast false positives (null|true|false|"")
		// ...but misinterprets leading-number strings, particularly hex literals ("0x...")
		// subtraction forces infinities to NaN
		// adding 1 corrects loss of precision from parseFloat (#15100)
		return !jQuery.isArray( obj ) && (obj - parseFloat( obj ) + 1) >= 0;
	},

	isEmptyObject: function( obj ) {
		var name;
		for ( name in obj ) {
			return false;
		}
		return true;
	},

	isPlainObject: function( obj ) {
		var key;

		// Must be an Object.
		// Because of IE, we also have to check the presence of the constructor property.
		// Make sure that DOM nodes and window objects don't pass through, as well
		if ( !obj || jQuery.type(obj) !== "object" || obj.nodeType || jQuery.isWindow( obj ) ) {
			return false;
		}

		try {
			// Not own constructor property must be Object
			if ( obj.constructor &&
				!hasOwn.call(obj, "constructor") &&
				!hasOwn.call(obj.constructor.prototype, "isPrototypeOf") ) {
				return false;
			}
		} catch ( e ) {
			// IE8,9 Will throw exceptions on certain host objects #9897
			return false;
		}

		// Support: IE<9
		// Handle iteration over inherited properties before own properties.
		if ( support.ownLast ) {
			for ( key in obj ) {
				return hasOwn.call( obj, key );
			}
		}

		// Own properties are enumerated firstly, so to speed up,
		// if last one is own, then all properties are own.
		for ( key in obj ) {}

		return key === undefined || hasOwn.call( obj, key );
	},

	type: function( obj ) {
		if ( obj == null ) {
			return obj + "";
		}
		return typeof obj === "object" || typeof obj === "function" ?
			class2type[ toString.call(obj) ] || "object" :
			typeof obj;
	},

	// Evaluates a script in a global context
	// Workarounds based on findings by Jim Driscoll
	// http://weblogs.java.net/blog/driscoll/archive/2009/09/08/eval-javascript-global-context
	globalEval: function( data ) {
		if ( data && jQuery.trim( data ) ) {
			// We use execScript on Internet Explorer
			// We use an anonymous function so that context is window
			// rather than jQuery in Firefox
			( window.execScript || function( data ) {
				window[ "eval" ].call( window, data );
			} )( data );
		}
	},

	// Convert dashed to camelCase; used by the css and data modules
	// Microsoft forgot to hump their vendor prefix (#9572)
	camelCase: function( string ) {
		return string.replace( rmsPrefix, "ms-" ).replace( rdashAlpha, fcamelCase );
	},

	nodeName: function( elem, name ) {
		return elem.nodeName && elem.nodeName.toLowerCase() === name.toLowerCase();
	},

	// args is for internal usage only
	each: function( obj, callback, args ) {
		var value,
			i = 0,
			length = obj.length,
			isArray = isArraylike( obj );

		if ( args ) {
			if ( isArray ) {
				for ( ; i < length; i++ ) {
					value = callback.apply( obj[ i ], args );

					if ( value === false ) {
						break;
					}
				}
			} else {
				for ( i in obj ) {
					value = callback.apply( obj[ i ], args );

					if ( value === false ) {
						break;
					}
				}
			}

		// A special, fast, case for the most common use of each
		} else {
			if ( isArray ) {
				for ( ; i < length; i++ ) {
					value = callback.call( obj[ i ], i, obj[ i ] );

					if ( value === false ) {
						break;
					}
				}
			} else {
				for ( i in obj ) {
					value = callback.call( obj[ i ], i, obj[ i ] );

					if ( value === false ) {
						break;
					}
				}
			}
		}

		return obj;
	},

	// Support: Android<4.1, IE<9
	trim: function( text ) {
		return text == null ?
			"" :
			( text + "" ).replace( rtrim, "" );
	},

	// results is for internal usage only
	makeArray: function( arr, results ) {
		var ret = results || [];

		if ( arr != null ) {
			if ( isArraylike( Object(arr) ) ) {
				jQuery.merge( ret,
					typeof arr === "string" ?
					[ arr ] : arr
				);
			} else {
				push.call( ret, arr );
			}
		}

		return ret;
	},

	inArray: function( elem, arr, i ) {
		var len;

		if ( arr ) {
			if ( indexOf ) {
				return indexOf.call( arr, elem, i );
			}

			len = arr.length;
			i = i ? i < 0 ? Math.max( 0, len + i ) : i : 0;

			for ( ; i < len; i++ ) {
				// Skip accessing in sparse arrays
				if ( i in arr && arr[ i ] === elem ) {
					return i;
				}
			}
		}

		return -1;
	},

	merge: function( first, second ) {
		var len = +second.length,
			j = 0,
			i = first.length;

		while ( j < len ) {
			first[ i++ ] = second[ j++ ];
		}

		// Support: IE<9
		// Workaround casting of .length to NaN on otherwise arraylike objects (e.g., NodeLists)
		if ( len !== len ) {
			while ( second[j] !== undefined ) {
				first[ i++ ] = second[ j++ ];
			}
		}

		first.length = i;

		return first;
	},

	grep: function( elems, callback, invert ) {
		var callbackInverse,
			matches = [],
			i = 0,
			length = elems.length,
			callbackExpect = !invert;

		// Go through the array, only saving the items
		// that pass the validator function
		for ( ; i < length; i++ ) {
			callbackInverse = !callback( elems[ i ], i );
			if ( callbackInverse !== callbackExpect ) {
				matches.push( elems[ i ] );
			}
		}

		return matches;
	},

	// arg is for internal usage only
	map: function( elems, callback, arg ) {
		var value,
			i = 0,
			length = elems.length,
			isArray = isArraylike( elems ),
			ret = [];

		// Go through the array, translating each of the items to their new values
		if ( isArray ) {
			for ( ; i < length; i++ ) {
				value = callback( elems[ i ], i, arg );

				if ( value != null ) {
					ret.push( value );
				}
			}

		// Go through every key on the object,
		} else {
			for ( i in elems ) {
				value = callback( elems[ i ], i, arg );

				if ( value != null ) {
					ret.push( value );
				}
			}
		}

		// Flatten any nested arrays
		return concat.apply( [], ret );
	},

	// A global GUID counter for objects
	guid: 1,

	// Bind a function to a context, optionally partially applying any
	// arguments.
	proxy: function( fn, context ) {
		var args, proxy, tmp;

		if ( typeof context === "string" ) {
			tmp = fn[ context ];
			context = fn;
			fn = tmp;
		}

		// Quick check to determine if target is callable, in the spec
		// this throws a TypeError, but we will just return undefined.
		if ( !jQuery.isFunction( fn ) ) {
			return undefined;
		}

		// Simulated bind
		args = slice.call( arguments, 2 );
		proxy = function() {
			return fn.apply( context || this, args.concat( slice.call( arguments ) ) );
		};

		// Set the guid of unique handler to the same of original handler, so it can be removed
		proxy.guid = fn.guid = fn.guid || jQuery.guid++;

		return proxy;
	},

	now: function() {
		return +( new Date() );
	},

	// jQuery.support is not used in Core but other projects attach their
	// properties to it so it needs to exist.
	support: support
});

// Populate the class2type map
jQuery.each("Boolean Number String Function Array Date RegExp Object Error".split(" "), function(i, name) {
	class2type[ "[object " + name + "]" ] = name.toLowerCase();
});

function isArraylike( obj ) {

	// Support: iOS 8.2 (not reproducible in simulator)
	// `in` check used to prevent JIT error (gh-2145)
	// hasOwn isn't used here due to false negatives
	// regarding Nodelist length in IE
	var length = "length" in obj && obj.length,
		type = jQuery.type( obj );

	if ( type === "function" || jQuery.isWindow( obj ) ) {
		return false;
	}

	if ( obj.nodeType === 1 && length ) {
		return true;
	}

	return type === "array" || length === 0 ||
		typeof length === "number" && length > 0 && ( length - 1 ) in obj;
}
var Sizzle =
/*!
 * Sizzle CSS Selector Engine v2.2.0-pre
 * http://sizzlejs.com/
 *
 * Copyright 2008, 2014 jQuery Foundation, Inc. and other contributors
 * Released under the MIT license
 * http://jquery.org/license
 *
 * Date: 2014-12-16
 */
(function( window ) {

var i,
	support,
	Expr,
	getText,
	isXML,
	tokenize,
	compile,
	select,
	outermostContext,
	sortInput,
	hasDuplicate,

	// Local document vars
	setDocument,
	document,
	docElem,
	documentIsHTML,
	rbuggyQSA,
	rbuggyMatches,
	matches,
	contains,

	// Instance-specific data
	expando = "sizzle" + 1 * new Date(),
	preferredDoc = window.document,
	dirruns = 0,
	done = 0,
	classCache = createCache(),
	tokenCache = createCache(),
	compilerCache = createCache(),
	sortOrder = function( a, b ) {
		if ( a === b ) {
			hasDuplicate = true;
		}
		return 0;
	},

	// General-purpose constants
	MAX_NEGATIVE = 1 << 31,

	// Instance methods
	hasOwn = ({}).hasOwnProperty,
	arr = [],
	pop = arr.pop,
	push_native = arr.push,
	push = arr.push,
	slice = arr.slice,
	// Use a stripped-down indexOf as it's faster than native
	// http://jsperf.com/thor-indexof-vs-for/5
	indexOf = function( list, elem ) {
		var i = 0,
			len = list.length;
		for ( ; i < len; i++ ) {
			if ( list[i] === elem ) {
				return i;
			}
		}
		return -1;
	},

	booleans = "checked|selected|async|autofocus|autoplay|controls|defer|disabled|hidden|ismap|loop|multiple|open|readonly|required|scoped",

	// Regular expressions

	// Whitespace characters http://www.w3.org/TR/css3-selectors/#whitespace
	whitespace = "[\\x20\\t\\r\\n\\f]",
	// http://www.w3.org/TR/css3-syntax/#characters
	characterEncoding = "(?:\\\\.|[\\w-]|[^\\x00-\\xa0])+",

	// Loosely modeled on CSS identifier characters
	// An unquoted value should be a CSS identifier http://www.w3.org/TR/css3-selectors/#attribute-selectors
	// Proper syntax: http://www.w3.org/TR/CSS21/syndata.html#value-def-identifier
	identifier = characterEncoding.replace( "w", "w#" ),

	// Attribute selectors: http://www.w3.org/TR/selectors/#attribute-selectors
	attributes = "\\[" + whitespace + "*(" + characterEncoding + ")(?:" + whitespace +
		// Operator (capture 2)
		"*([*^$|!~]?=)" + whitespace +
		// "Attribute values must be CSS identifiers [capture 5] or strings [capture 3 or capture 4]"
		"*(?:'((?:\\\\.|[^\\\\'])*)'|\"((?:\\\\.|[^\\\\\"])*)\"|(" + identifier + "))|)" + whitespace +
		"*\\]",

	pseudos = ":(" + characterEncoding + ")(?:\\((" +
		// To reduce the number of selectors needing tokenize in the preFilter, prefer arguments:
		// 1. quoted (capture 3; capture 4 or capture 5)
		"('((?:\\\\.|[^\\\\'])*)'|\"((?:\\\\.|[^\\\\\"])*)\")|" +
		// 2. simple (capture 6)
		"((?:\\\\.|[^\\\\()[\\]]|" + attributes + ")*)|" +
		// 3. anything else (capture 2)
		".*" +
		")\\)|)",

	// Leading and non-escaped trailing whitespace, capturing some non-whitespace characters preceding the latter
	rwhitespace = new RegExp( whitespace + "+", "g" ),
	rtrim = new RegExp( "^" + whitespace + "+|((?:^|[^\\\\])(?:\\\\.)*)" + whitespace + "+$", "g" ),

	rcomma = new RegExp( "^" + whitespace + "*," + whitespace + "*" ),
	rcombinators = new RegExp( "^" + whitespace + "*([>+~]|" + whitespace + ")" + whitespace + "*" ),

	rattributeQuotes = new RegExp( "=" + whitespace + "*([^\\]'\"]*?)" + whitespace + "*\\]", "g" ),

	rpseudo = new RegExp( pseudos ),
	ridentifier = new RegExp( "^" + identifier + "$" ),

	matchExpr = {
		"ID": new RegExp( "^#(" + characterEncoding + ")" ),
		"CLASS": new RegExp( "^\\.(" + characterEncoding + ")" ),
		"TAG": new RegExp( "^(" + characterEncoding.replace( "w", "w*" ) + ")" ),
		"ATTR": new RegExp( "^" + attributes ),
		"PSEUDO": new RegExp( "^" + pseudos ),
		"CHILD": new RegExp( "^:(only|first|last|nth|nth-last)-(child|of-type)(?:\\(" + whitespace +
			"*(even|odd|(([+-]|)(\\d*)n|)" + whitespace + "*(?:([+-]|)" + whitespace +
			"*(\\d+)|))" + whitespace + "*\\)|)", "i" ),
		"bool": new RegExp( "^(?:" + booleans + ")$", "i" ),
		// For use in libraries implementing .is()
		// We use this for POS matching in `select`
		"needsContext": new RegExp( "^" + whitespace + "*[>+~]|:(even|odd|eq|gt|lt|nth|first|last)(?:\\(" +
			whitespace + "*((?:-\\d)?\\d*)" + whitespace + "*\\)|)(?=[^-]|$)", "i" )
	},

	rinputs = /^(?:input|select|textarea|button)$/i,
	rheader = /^h\d$/i,

	rnative = /^[^{]+\{\s*\[native \w/,

	// Easily-parseable/retrievable ID or TAG or CLASS selectors
	rquickExpr = /^(?:#([\w-]+)|(\w+)|\.([\w-]+))$/,

	rsibling = /[+~]/,
	rescape = /'|\\/g,

	// CSS escapes http://www.w3.org/TR/CSS21/syndata.html#escaped-characters
	runescape = new RegExp( "\\\\([\\da-f]{1,6}" + whitespace + "?|(" + whitespace + ")|.)", "ig" ),
	funescape = function( _, escaped, escapedWhitespace ) {
		var high = "0x" + escaped - 0x10000;
		// NaN means non-codepoint
		// Support: Firefox<24
		// Workaround erroneous numeric interpretation of +"0x"
		return high !== high || escapedWhitespace ?
			escaped :
			high < 0 ?
				// BMP codepoint
				String.fromCharCode( high + 0x10000 ) :
				// Supplemental Plane codepoint (surrogate pair)
				String.fromCharCode( high >> 10 | 0xD800, high & 0x3FF | 0xDC00 );
	},

	// Used for iframes
	// See setDocument()
	// Removing the function wrapper causes a "Permission Denied"
	// error in IE
	unloadHandler = function() {
		setDocument();
	};

// Optimize for push.apply( _, NodeList )
try {
	push.apply(
		(arr = slice.call( preferredDoc.childNodes )),
		preferredDoc.childNodes
	);
	// Support: Android<4.0
	// Detect silently failing push.apply
	arr[ preferredDoc.childNodes.length ].nodeType;
} catch ( e ) {
	push = { apply: arr.length ?

		// Leverage slice if possible
		function( target, els ) {
			push_native.apply( target, slice.call(els) );
		} :

		// Support: IE<9
		// Otherwise append directly
		function( target, els ) {
			var j = target.length,
				i = 0;
			// Can't trust NodeList.length
			while ( (target[j++] = els[i++]) ) {}
			target.length = j - 1;
		}
	};
}

function Sizzle( selector, context, results, seed ) {
	var match, elem, m, nodeType,
		// QSA vars
		i, groups, old, nid, newContext, newSelector;

	if ( ( context ? context.ownerDocument || context : preferredDoc ) !== document ) {
		setDocument( context );
	}

	context = context || document;
	results = results || [];
	nodeType = context.nodeType;

	if ( typeof selector !== "string" || !selector ||
		nodeType !== 1 && nodeType !== 9 && nodeType !== 11 ) {

		return results;
	}

	if ( !seed && documentIsHTML ) {

		// Try to shortcut find operations when possible (e.g., not under DocumentFragment)
		if ( nodeType !== 11 && (match = rquickExpr.exec( selector )) ) {
			// Speed-up: Sizzle("#ID")
			if ( (m = match[1]) ) {
				if ( nodeType === 9 ) {
					elem = context.getElementById( m );
					// Check parentNode to catch when Blackberry 4.6 returns
					// nodes that are no longer in the document (jQuery #6963)
					if ( elem && elem.parentNode ) {
						// Handle the case where IE, Opera, and Webkit return items
						// by name instead of ID
						if ( elem.id === m ) {
							results.push( elem );
							return results;
						}
					} else {
						return results;
					}
				} else {
					// Context is not a document
					if ( context.ownerDocument && (elem = context.ownerDocument.getElementById( m )) &&
						contains( context, elem ) && elem.id === m ) {
						results.push( elem );
						return results;
					}
				}

			// Speed-up: Sizzle("TAG")
			} else if ( match[2] ) {
				push.apply( results, context.getElementsByTagName( selector ) );
				return results;

			// Speed-up: Sizzle(".CLASS")
			} else if ( (m = match[3]) && support.getElementsByClassName ) {
				push.apply( results, context.getElementsByClassName( m ) );
				return results;
			}
		}

		// QSA path
		if ( support.qsa && (!rbuggyQSA || !rbuggyQSA.test( selector )) ) {
			nid = old = expando;
			newContext = context;
			newSelector = nodeType !== 1 && selector;

			// qSA works strangely on Element-rooted queries
			// We can work around this by specifying an extra ID on the root
			// and working up from there (Thanks to Andrew Dupont for the technique)
			// IE 8 doesn't work on object elements
			if ( nodeType === 1 && context.nodeName.toLowerCase() !== "object" ) {
				groups = tokenize( selector );

				if ( (old = context.getAttribute("id")) ) {
					nid = old.replace( rescape, "\\$&" );
				} else {
					context.setAttribute( "id", nid );
				}
				nid = "[id='" + nid + "'] ";

				i = groups.length;
				while ( i-- ) {
					groups[i] = nid + toSelector( groups[i] );
				}
				newContext = rsibling.test( selector ) && testContext( context.parentNode ) || context;
				newSelector = groups.join(",");
			}

			if ( newSelector ) {
				try {
					push.apply( results,
						newContext.querySelectorAll( newSelector )
					);
					return results;
				} catch(qsaError) {
				} finally {
					if ( !old ) {
						context.removeAttribute("id");
					}
				}
			}
		}
	}

	// All others
	return select( selector.replace( rtrim, "$1" ), context, results, seed );
}

/**
 * Create key-value caches of limited size
 * @returns {Function(string, Object)} Returns the Object data after storing it on itself with
 *	property name the (space-suffixed) string and (if the cache is larger than Expr.cacheLength)
 *	deleting the oldest entry
 */
function createCache() {
	var keys = [];

	function cache( key, value ) {
		// Use (key + " ") to avoid collision with native prototype properties (see Issue #157)
		if ( keys.push( key + " " ) > Expr.cacheLength ) {
			// Only keep the most recent entries
			delete cache[ keys.shift() ];
		}
		return (cache[ key + " " ] = value);
	}
	return cache;
}

/**
 * Mark a function for special use by Sizzle
 * @param {Function} fn The function to mark
 */
function markFunction( fn ) {
	fn[ expando ] = true;
	return fn;
}

/**
 * Support testing using an element
 * @param {Function} fn Passed the created div and expects a boolean result
 */
function assert( fn ) {
	var div = document.createElement("div");

	try {
		return !!fn( div );
	} catch (e) {
		return false;
	} finally {
		// Remove from its parent by default
		if ( div.parentNode ) {
			div.parentNode.removeChild( div );
		}
		// release memory in IE
		div = null;
	}
}

/**
 * Adds the same handler for all of the specified attrs
 * @param {String} attrs Pipe-separated list of attributes
 * @param {Function} handler The method that will be applied
 */
function addHandle( attrs, handler ) {
	var arr = attrs.split("|"),
		i = attrs.length;

	while ( i-- ) {
		Expr.attrHandle[ arr[i] ] = handler;
	}
}

/**
 * Checks document order of two siblings
 * @param {Element} a
 * @param {Element} b
 * @returns {Number} Returns less than 0 if a precedes b, greater than 0 if a follows b
 */
function siblingCheck( a, b ) {
	var cur = b && a,
		diff = cur && a.nodeType === 1 && b.nodeType === 1 &&
			( ~b.sourceIndex || MAX_NEGATIVE ) -
			( ~a.sourceIndex || MAX_NEGATIVE );

	// Use IE sourceIndex if available on both nodes
	if ( diff ) {
		return diff;
	}

	// Check if b follows a
	if ( cur ) {
		while ( (cur = cur.nextSibling) ) {
			if ( cur === b ) {
				return -1;
			}
		}
	}

	return a ? 1 : -1;
}

/**
 * Returns a function to use in pseudos for input types
 * @param {String} type
 */
function createInputPseudo( type ) {
	return function( elem ) {
		var name = elem.nodeName.toLowerCase();
		return name === "input" && elem.type === type;
	};
}

/**
 * Returns a function to use in pseudos for buttons
 * @param {String} type
 */
function createButtonPseudo( type ) {
	return function( elem ) {
		var name = elem.nodeName.toLowerCase();
		return (name === "input" || name === "button") && elem.type === type;
	};
}

/**
 * Returns a function to use in pseudos for positionals
 * @param {Function} fn
 */
function createPositionalPseudo( fn ) {
	return markFunction(function( argument ) {
		argument = +argument;
		return markFunction(function( seed, matches ) {
			var j,
				matchIndexes = fn( [], seed.length, argument ),
				i = matchIndexes.length;

			// Match elements found at the specified indexes
			while ( i-- ) {
				if ( seed[ (j = matchIndexes[i]) ] ) {
					seed[j] = !(matches[j] = seed[j]);
				}
			}
		});
	});
}

/**
 * Checks a node for validity as a Sizzle context
 * @param {Element|Object=} context
 * @returns {Element|Object|Boolean} The input node if acceptable, otherwise a falsy value
 */
function testContext( context ) {
	return context && typeof context.getElementsByTagName !== "undefined" && context;
}

// Expose support vars for convenience
support = Sizzle.support = {};

/**
 * Detects XML nodes
 * @param {Element|Object} elem An element or a document
 * @returns {Boolean} True iff elem is a non-HTML XML node
 */
isXML = Sizzle.isXML = function( elem ) {
	// documentElement is verified for cases where it doesn't yet exist
	// (such as loading iframes in IE - #4833)
	var documentElement = elem && (elem.ownerDocument || elem).documentElement;
	return documentElement ? documentElement.nodeName !== "HTML" : false;
};

/**
 * Sets document-related variables once based on the current document
 * @param {Element|Object} [doc] An element or document object to use to set the document
 * @returns {Object} Returns the current document
 */
setDocument = Sizzle.setDocument = function( node ) {
	var hasCompare, parent,
		doc = node ? node.ownerDocument || node : preferredDoc;

	// If no document and documentElement is available, return
	if ( doc === document || doc.nodeType !== 9 || !doc.documentElement ) {
		return document;
	}

	// Set our document
	document = doc;
	docElem = doc.documentElement;
	parent = doc.defaultView;

	// Support: IE>8
	// If iframe document is assigned to "document" variable and if iframe has been reloaded,
	// IE will throw "permission denied" error when accessing "document" variable, see jQuery #13936
	// IE6-8 do not support the defaultView property so parent will be undefined
	if ( parent && parent !== parent.top ) {
		// IE11 does not have attachEvent, so all must suffer
		if ( parent.addEventListener ) {
			parent.addEventListener( "unload", unloadHandler, false );
		} else if ( parent.attachEvent ) {
			parent.attachEvent( "onunload", unloadHandler );
		}
	}

	/* Support tests
	---------------------------------------------------------------------- */
	documentIsHTML = !isXML( doc );

	/* Attributes
	---------------------------------------------------------------------- */

	// Support: IE<8
	// Verify that getAttribute really returns attributes and not properties
	// (excepting IE8 booleans)
	support.attributes = assert(function( div ) {
		div.className = "i";
		return !div.getAttribute("className");
	});

	/* getElement(s)By*
	---------------------------------------------------------------------- */

	// Check if getElementsByTagName("*") returns only elements
	support.getElementsByTagName = assert(function( div ) {
		div.appendChild( doc.createComment("") );
		return !div.getElementsByTagName("*").length;
	});

	// Support: IE<9
	support.getElementsByClassName = rnative.test( doc.getElementsByClassName );

	// Support: IE<10
	// Check if getElementById returns elements by name
	// The broken getElementById methods don't pick up programatically-set names,
	// so use a roundabout getElementsByName test
	support.getById = assert(function( div ) {
		docElem.appendChild( div ).id = expando;
		return !doc.getElementsByName || !doc.getElementsByName( expando ).length;
	});

	// ID find and filter
	if ( support.getById ) {
		Expr.find["ID"] = function( id, context ) {
			if ( typeof context.getElementById !== "undefined" && documentIsHTML ) {
				var m = context.getElementById( id );
				// Check parentNode to catch when Blackberry 4.6 returns
				// nodes that are no longer in the document #6963
				return m && m.parentNode ? [ m ] : [];
			}
		};
		Expr.filter["ID"] = function( id ) {
			var attrId = id.replace( runescape, funescape );
			return function( elem ) {
				return elem.getAttribute("id") === attrId;
			};
		};
	} else {
		// Support: IE6/7
		// getElementById is not reliable as a find shortcut
		delete Expr.find["ID"];

		Expr.filter["ID"] =  function( id ) {
			var attrId = id.replace( runescape, funescape );
			return function( elem ) {
				var node = typeof elem.getAttributeNode !== "undefined" && elem.getAttributeNode("id");
				return node && node.value === attrId;
			};
		};
	}

	// Tag
	Expr.find["TAG"] = support.getElementsByTagName ?
		function( tag, context ) {
			if ( typeof context.getElementsByTagName !== "undefined" ) {
				return context.getElementsByTagName( tag );

			// DocumentFragment nodes don't have gEBTN
			} else if ( support.qsa ) {
				return context.querySelectorAll( tag );
			}
		} :

		function( tag, context ) {
			var elem,
				tmp = [],
				i = 0,
				// By happy coincidence, a (broken) gEBTN appears on DocumentFragment nodes too
				results = context.getElementsByTagName( tag );

			// Filter out possible comments
			if ( tag === "*" ) {
				while ( (elem = results[i++]) ) {
					if ( elem.nodeType === 1 ) {
						tmp.push( elem );
					}
				}

				return tmp;
			}
			return results;
		};

	// Class
	Expr.find["CLASS"] = support.getElementsByClassName && function( className, context ) {
		if ( documentIsHTML ) {
			return context.getElementsByClassName( className );
		}
	};

	/* QSA/matchesSelector
	---------------------------------------------------------------------- */

	// QSA and matchesSelector support

	// matchesSelector(:active) reports false when true (IE9/Opera 11.5)
	rbuggyMatches = [];

	// qSa(:focus) reports false when true (Chrome 21)
	// We allow this because of a bug in IE8/9 that throws an error
	// whenever `document.activeElement` is accessed on an iframe
	// So, we allow :focus to pass through QSA all the time to avoid the IE error
	// See http://bugs.jquery.com/ticket/13378
	rbuggyQSA = [];

	if ( (support.qsa = rnative.test( doc.querySelectorAll )) ) {
		// Build QSA regex
		// Regex strategy adopted from Diego Perini
		assert(function( div ) {
			// Select is set to empty string on purpose
			// This is to test IE's treatment of not explicitly
			// setting a boolean content attribute,
			// since its presence should be enough
			// http://bugs.jquery.com/ticket/12359
			docElem.appendChild( div ).innerHTML = "<a id='" + expando + "'></a>" +
				"<select id='" + expando + "-\f]' msallowcapture=''>" +
				"<option selected=''></option></select>";

			// Support: IE8, Opera 11-12.16
			// Nothing should be selected when empty strings follow ^= or $= or *=
			// The test attribute must be unknown in Opera but "safe" for WinRT
			// http://msdn.microsoft.com/en-us/library/ie/hh465388.aspx#attribute_section
			if ( div.querySelectorAll("[msallowcapture^='']").length ) {
				rbuggyQSA.push( "[*^$]=" + whitespace + "*(?:''|\"\")" );
			}

			// Support: IE8
			// Boolean attributes and "value" are not treated correctly
			if ( !div.querySelectorAll("[selected]").length ) {
				rbuggyQSA.push( "\\[" + whitespace + "*(?:value|" + booleans + ")" );
			}

			// Support: Chrome<29, Android<4.2+, Safari<7.0+, iOS<7.0+, PhantomJS<1.9.7+
			if ( !div.querySelectorAll( "[id~=" + expando + "-]" ).length ) {
				rbuggyQSA.push("~=");
			}

			// Webkit/Opera - :checked should return selected option elements
			// http://www.w3.org/TR/2011/REC-css3-selectors-20110929/#checked
			// IE8 throws error here and will not see later tests
			if ( !div.querySelectorAll(":checked").length ) {
				rbuggyQSA.push(":checked");
			}

			// Support: Safari 8+, iOS 8+
			// https://bugs.webkit.org/show_bug.cgi?id=136851
			// In-page `selector#id sibing-combinator selector` fails
			if ( !div.querySelectorAll( "a#" + expando + "+*" ).length ) {
				rbuggyQSA.push(".#.+[+~]");
			}
		});

		assert(function( div ) {
			// Support: Windows 8 Native Apps
			// The type and name attributes are restricted during .innerHTML assignment
			var input = doc.createElement("input");
			input.setAttribute( "type", "hidden" );
			div.appendChild( input ).setAttribute( "name", "D" );

			// Support: IE8
			// Enforce case-sensitivity of name attribute
			if ( div.querySelectorAll("[name=d]").length ) {
				rbuggyQSA.push( "name" + whitespace + "*[*^$|!~]?=" );
			}

			// FF 3.5 - :enabled/:disabled and hidden elements (hidden elements are still enabled)
			// IE8 throws error here and will not see later tests
			if ( !div.querySelectorAll(":enabled").length ) {
				rbuggyQSA.push( ":enabled", ":disabled" );
			}

			// Opera 10-11 does not throw on post-comma invalid pseudos
			div.querySelectorAll("*,:x");
			rbuggyQSA.push(",.*:");
		});
	}

	if ( (support.matchesSelector = rnative.test( (matches = docElem.matches ||
		docElem.webkitMatchesSelector ||
		docElem.mozMatchesSelector ||
		docElem.oMatchesSelector ||
		docElem.msMatchesSelector) )) ) {

		assert(function( div ) {
			// Check to see if it's possible to do matchesSelector
			// on a disconnected node (IE 9)
			support.disconnectedMatch = matches.call( div, "div" );

			// This should fail with an exception
			// Gecko does not error, returns false instead
			matches.call( div, "[s!='']:x" );
			rbuggyMatches.push( "!=", pseudos );
		});
	}

	rbuggyQSA = rbuggyQSA.length && new RegExp( rbuggyQSA.join("|") );
	rbuggyMatches = rbuggyMatches.length && new RegExp( rbuggyMatches.join("|") );

	/* Contains
	---------------------------------------------------------------------- */
	hasCompare = rnative.test( docElem.compareDocumentPosition );

	// Element contains another
	// Purposefully does not implement inclusive descendent
	// As in, an element does not contain itself
	contains = hasCompare || rnative.test( docElem.contains ) ?
		function( a, b ) {
			var adown = a.nodeType === 9 ? a.documentElement : a,
				bup = b && b.parentNode;
			return a === bup || !!( bup && bup.nodeType === 1 && (
				adown.contains ?
					adown.contains( bup ) :
					a.compareDocumentPosition && a.compareDocumentPosition( bup ) & 16
			));
		} :
		function( a, b ) {
			if ( b ) {
				while ( (b = b.parentNode) ) {
					if ( b === a ) {
						return true;
					}
				}
			}
			return false;
		};

	/* Sorting
	---------------------------------------------------------------------- */

	// Document order sorting
	sortOrder = hasCompare ?
	function( a, b ) {

		// Flag for duplicate removal
		if ( a === b ) {
			hasDuplicate = true;
			return 0;
		}

		// Sort on method existence if only one input has compareDocumentPosition
		var compare = !a.compareDocumentPosition - !b.compareDocumentPosition;
		if ( compare ) {
			return compare;
		}

		// Calculate position if both inputs belong to the same document
		compare = ( a.ownerDocument || a ) === ( b.ownerDocument || b ) ?
			a.compareDocumentPosition( b ) :

			// Otherwise we know they are disconnected
			1;

		// Disconnected nodes
		if ( compare & 1 ||
			(!support.sortDetached && b.compareDocumentPosition( a ) === compare) ) {

			// Choose the first element that is related to our preferred document
			if ( a === doc || a.ownerDocument === preferredDoc && contains(preferredDoc, a) ) {
				return -1;
			}
			if ( b === doc || b.ownerDocument === preferredDoc && contains(preferredDoc, b) ) {
				return 1;
			}

			// Maintain original order
			return sortInput ?
				( indexOf( sortInput, a ) - indexOf( sortInput, b ) ) :
				0;
		}

		return compare & 4 ? -1 : 1;
	} :
	function( a, b ) {
		// Exit early if the nodes are identical
		if ( a === b ) {
			hasDuplicate = true;
			return 0;
		}

		var cur,
			i = 0,
			aup = a.parentNode,
			bup = b.parentNode,
			ap = [ a ],
			bp = [ b ];

		// Parentless nodes are either documents or disconnected
		if ( !aup || !bup ) {
			return a === doc ? -1 :
				b === doc ? 1 :
				aup ? -1 :
				bup ? 1 :
				sortInput ?
				( indexOf( sortInput, a ) - indexOf( sortInput, b ) ) :
				0;

		// If the nodes are siblings, we can do a quick check
		} else if ( aup === bup ) {
			return siblingCheck( a, b );
		}

		// Otherwise we need full lists of their ancestors for comparison
		cur = a;
		while ( (cur = cur.parentNode) ) {
			ap.unshift( cur );
		}
		cur = b;
		while ( (cur = cur.parentNode) ) {
			bp.unshift( cur );
		}

		// Walk down the tree looking for a discrepancy
		while ( ap[i] === bp[i] ) {
			i++;
		}

		return i ?
			// Do a sibling check if the nodes have a common ancestor
			siblingCheck( ap[i], bp[i] ) :

			// Otherwise nodes in our document sort first
			ap[i] === preferredDoc ? -1 :
			bp[i] === preferredDoc ? 1 :
			0;
	};

	return doc;
};

Sizzle.matches = function( expr, elements ) {
	return Sizzle( expr, null, null, elements );
};

Sizzle.matchesSelector = function( elem, expr ) {
	// Set document vars if needed
	if ( ( elem.ownerDocument || elem ) !== document ) {
		setDocument( elem );
	}

	// Make sure that attribute selectors are quoted
	expr = expr.replace( rattributeQuotes, "='$1']" );

	if ( support.matchesSelector && documentIsHTML &&
		( !rbuggyMatches || !rbuggyMatches.test( expr ) ) &&
		( !rbuggyQSA     || !rbuggyQSA.test( expr ) ) ) {

		try {
			var ret = matches.call( elem, expr );

			// IE 9's matchesSelector returns false on disconnected nodes
			if ( ret || support.disconnectedMatch ||
					// As well, disconnected nodes are said to be in a document
					// fragment in IE 9
					elem.document && elem.document.nodeType !== 11 ) {
				return ret;
			}
		} catch (e) {}
	}

	return Sizzle( expr, document, null, [ elem ] ).length > 0;
};

Sizzle.contains = function( context, elem ) {
	// Set document vars if needed
	if ( ( context.ownerDocument || context ) !== document ) {
		setDocument( context );
	}
	return contains( context, elem );
};

Sizzle.attr = function( elem, name ) {
	// Set document vars if needed
	if ( ( elem.ownerDocument || elem ) !== document ) {
		setDocument( elem );
	}

	var fn = Expr.attrHandle[ name.toLowerCase() ],
		// Don't get fooled by Object.prototype properties (jQuery #13807)
		val = fn && hasOwn.call( Expr.attrHandle, name.toLowerCase() ) ?
			fn( elem, name, !documentIsHTML ) :
			undefined;

	return val !== undefined ?
		val :
		support.attributes || !documentIsHTML ?
			elem.getAttribute( name ) :
			(val = elem.getAttributeNode(name)) && val.specified ?
				val.value :
				null;
};

Sizzle.error = function( msg ) {
	throw new Error( "Syntax error, unrecognized expression: " + msg );
};

/**
 * Document sorting and removing duplicates
 * @param {ArrayLike} results
 */
Sizzle.uniqueSort = function( results ) {
	var elem,
		duplicates = [],
		j = 0,
		i = 0;

	// Unless we *know* we can detect duplicates, assume their presence
	hasDuplicate = !support.detectDuplicates;
	sortInput = !support.sortStable && results.slice( 0 );
	results.sort( sortOrder );

	if ( hasDuplicate ) {
		while ( (elem = results[i++]) ) {
			if ( elem === results[ i ] ) {
				j = duplicates.push( i );
			}
		}
		while ( j-- ) {
			results.splice( duplicates[ j ], 1 );
		}
	}

	// Clear input after sorting to release objects
	// See https://github.com/jquery/sizzle/pull/225
	sortInput = null;

	return results;
};

/**
 * Utility function for retrieving the text value of an array of DOM nodes
 * @param {Array|Element} elem
 */
getText = Sizzle.getText = function( elem ) {
	var node,
		ret = "",
		i = 0,
		nodeType = elem.nodeType;

	if ( !nodeType ) {
		// If no nodeType, this is expected to be an array
		while ( (node = elem[i++]) ) {
			// Do not traverse comment nodes
			ret += getText( node );
		}
	} else if ( nodeType === 1 || nodeType === 9 || nodeType === 11 ) {
		// Use textContent for elements
		// innerText usage removed for consistency of new lines (jQuery #11153)
		if ( typeof elem.textContent === "string" ) {
			return elem.textContent;
		} else {
			// Traverse its children
			for ( elem = elem.firstChild; elem; elem = elem.nextSibling ) {
				ret += getText( elem );
			}
		}
	} else if ( nodeType === 3 || nodeType === 4 ) {
		return elem.nodeValue;
	}
	// Do not include comment or processing instruction nodes

	return ret;
};

Expr = Sizzle.selectors = {

	// Can be adjusted by the user
	cacheLength: 50,

	createPseudo: markFunction,

	match: matchExpr,

	attrHandle: {},

	find: {},

	relative: {
		">": { dir: "parentNode", first: true },
		" ": { dir: "parentNode" },
		"+": { dir: "previousSibling", first: true },
		"~": { dir: "previousSibling" }
	},

	preFilter: {
		"ATTR": function( match ) {
			match[1] = match[1].replace( runescape, funescape );

			// Move the given value to match[3] whether quoted or unquoted
			match[3] = ( match[3] || match[4] || match[5] || "" ).replace( runescape, funescape );

			if ( match[2] === "~=" ) {
				match[3] = " " + match[3] + " ";
			}

			return match.slice( 0, 4 );
		},

		"CHILD": function( match ) {
			/* matches from matchExpr["CHILD"]
				1 type (only|nth|...)
				2 what (child|of-type)
				3 argument (even|odd|\d*|\d*n([+-]\d+)?|...)
				4 xn-component of xn+y argument ([+-]?\d*n|)
				5 sign of xn-component
				6 x of xn-component
				7 sign of y-component
				8 y of y-component
			*/
			match[1] = match[1].toLowerCase();

			if ( match[1].slice( 0, 3 ) === "nth" ) {
				// nth-* requires argument
				if ( !match[3] ) {
					Sizzle.error( match[0] );
				}

				// numeric x and y parameters for Expr.filter.CHILD
				// remember that false/true cast respectively to 0/1
				match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === "even" || match[3] === "odd" ) );
				match[5] = +( ( match[7] + match[8] ) || match[3] === "odd" );

			// other types prohibit arguments
			} else if ( match[3] ) {
				Sizzle.error( match[0] );
			}

			return match;
		},

		"PSEUDO": function( match ) {
			var excess,
				unquoted = !match[6] && match[2];

			if ( matchExpr["CHILD"].test( match[0] ) ) {
				return null;
			}

			// Accept quoted arguments as-is
			if ( match[3] ) {
				match[2] = match[4] || match[5] || "";

			// Strip excess characters from unquoted arguments
			} else if ( unquoted && rpseudo.test( unquoted ) &&
				// Get excess from tokenize (recursively)
				(excess = tokenize( unquoted, true )) &&
				// advance to the next closing parenthesis
				(excess = unquoted.indexOf( ")", unquoted.length - excess ) - unquoted.length) ) {

				// excess is a negative index
				match[0] = match[0].slice( 0, excess );
				match[2] = unquoted.slice( 0, excess );
			}

			// Return only captures needed by the pseudo filter method (type and argument)
			return match.slice( 0, 3 );
		}
	},

	filter: {

		"TAG": function( nodeNameSelector ) {
			var nodeName = nodeNameSelector.replace( runescape, funescape ).toLowerCase();
			return nodeNameSelector === "*" ?
				function() { return true; } :
				function( elem ) {
					return elem.nodeName && elem.nodeName.toLowerCase() === nodeName;
				};
		},

		"CLASS": function( className ) {
			var pattern = classCache[ className + " " ];

			return pattern ||
				(pattern = new RegExp( "(^|" + whitespace + ")" + className + "(" + whitespace + "|$)" )) &&
				classCache( className, function( elem ) {
					return pattern.test( typeof elem.className === "string" && elem.className || typeof elem.getAttribute !== "undefined" && elem.getAttribute("class") || "" );
				});
		},

		"ATTR": function( name, operator, check ) {
			return function( elem ) {
				var result = Sizzle.attr( elem, name );

				if ( result == null ) {
					return operator === "!=";
				}
				if ( !operator ) {
					return true;
				}

				result += "";

				return operator === "=" ? result === check :
					operator === "!=" ? result !== check :
					operator === "^=" ? check && result.indexOf( check ) === 0 :
					operator === "*=" ? check && result.indexOf( check ) > -1 :
					operator === "$=" ? check && result.slice( -check.length ) === check :
					operator === "~=" ? ( " " + result.replace( rwhitespace, " " ) + " " ).indexOf( check ) > -1 :
					operator === "|=" ? result === check || result.slice( 0, check.length + 1 ) === check + "-" :
					false;
			};
		},

		"CHILD": function( type, what, argument, first, last ) {
			var simple = type.slice( 0, 3 ) !== "nth",
				forward = type.slice( -4 ) !== "last",
				ofType = what === "of-type";

			return first === 1 && last === 0 ?

				// Shortcut for :nth-*(n)
				function( elem ) {
					return !!elem.parentNode;
				} :

				function( elem, context, xml ) {
					var cache, outerCache, node, diff, nodeIndex, start,
						dir = simple !== forward ? "nextSibling" : "previousSibling",
						parent = elem.parentNode,
						name = ofType && elem.nodeName.toLowerCase(),
						useCache = !xml && !ofType;

					if ( parent ) {

						// :(first|last|only)-(child|of-type)
						if ( simple ) {
							while ( dir ) {
								node = elem;
								while ( (node = node[ dir ]) ) {
									if ( ofType ? node.nodeName.toLowerCase() === name : node.nodeType === 1 ) {
										return false;
									}
								}
								// Reverse direction for :only-* (if we haven't yet done so)
								start = dir = type === "only" && !start && "nextSibling";
							}
							return true;
						}

						start = [ forward ? parent.firstChild : parent.lastChild ];

						// non-xml :nth-child(...) stores cache data on `parent`
						if ( forward && useCache ) {
							// Seek `elem` from a previously-cached index
							outerCache = parent[ expando ] || (parent[ expando ] = {});
							cache = outerCache[ type ] || [];
							nodeIndex = cache[0] === dirruns && cache[1];
							diff = cache[0] === dirruns && cache[2];
							node = nodeIndex && parent.childNodes[ nodeIndex ];

							while ( (node = ++nodeIndex && node && node[ dir ] ||

								// Fallback to seeking `elem` from the start
								(diff = nodeIndex = 0) || start.pop()) ) {

								// When found, cache indexes on `parent` and break
								if ( node.nodeType === 1 && ++diff && node === elem ) {
									outerCache[ type ] = [ dirruns, nodeIndex, diff ];
									break;
								}
							}

						// Use previously-cached element index if available
						} else if ( useCache && (cache = (elem[ expando ] || (elem[ expando ] = {}))[ type ]) && cache[0] === dirruns ) {
							diff = cache[1];

						// xml :nth-child(...) or :nth-last-child(...) or :nth(-last)?-of-type(...)
						} else {
							// Use the same loop as above to seek `elem` from the start
							while ( (node = ++nodeIndex && node && node[ dir ] ||
								(diff = nodeIndex = 0) || start.pop()) ) {

								if ( ( ofType ? node.nodeName.toLowerCase() === name : node.nodeType === 1 ) && ++diff ) {
									// Cache the index of each encountered element
									if ( useCache ) {
										(node[ expando ] || (node[ expando ] = {}))[ type ] = [ dirruns, diff ];
									}

									if ( node === elem ) {
										break;
									}
								}
							}
						}

						// Incorporate the offset, then check against cycle size
						diff -= last;
						return diff === first || ( diff % first === 0 && diff / first >= 0 );
					}
				};
		},

		"PSEUDO": function( pseudo, argument ) {
			// pseudo-class names are case-insensitive
			// http://www.w3.org/TR/selectors/#pseudo-classes
			// Prioritize by case sensitivity in case custom pseudos are added with uppercase letters
			// Remember that setFilters inherits from pseudos
			var args,
				fn = Expr.pseudos[ pseudo ] || Expr.setFilters[ pseudo.toLowerCase() ] ||
					Sizzle.error( "unsupported pseudo: " + pseudo );

			// The user may use createPseudo to indicate that
			// arguments are needed to create the filter function
			// just as Sizzle does
			if ( fn[ expando ] ) {
				return fn( argument );
			}

			// But maintain support for old signatures
			if ( fn.length > 1 ) {
				args = [ pseudo, pseudo, "", argument ];
				return Expr.setFilters.hasOwnProperty( pseudo.toLowerCase() ) ?
					markFunction(function( seed, matches ) {
						var idx,
							matched = fn( seed, argument ),
							i = matched.length;
						while ( i-- ) {
							idx = indexOf( seed, matched[i] );
							seed[ idx ] = !( matches[ idx ] = matched[i] );
						}
					}) :
					function( elem ) {
						return fn( elem, 0, args );
					};
			}

			return fn;
		}
	},

	pseudos: {
		// Potentially complex pseudos
		"not": markFunction(function( selector ) {
			// Trim the selector passed to compile
			// to avoid treating leading and trailing
			// spaces as combinators
			var input = [],
				results = [],
				matcher = compile( selector.replace( rtrim, "$1" ) );

			return matcher[ expando ] ?
				markFunction(function( seed, matches, context, xml ) {
					var elem,
						unmatched = matcher( seed, null, xml, [] ),
						i = seed.length;

					// Match elements unmatched by `matcher`
					while ( i-- ) {
						if ( (elem = unmatched[i]) ) {
							seed[i] = !(matches[i] = elem);
						}
					}
				}) :
				function( elem, context, xml ) {
					input[0] = elem;
					matcher( input, null, xml, results );
					// Don't keep the element (issue #299)
					input[0] = null;
					return !results.pop();
				};
		}),

		"has": markFunction(function( selector ) {
			return function( elem ) {
				return Sizzle( selector, elem ).length > 0;
			};
		}),

		"contains": markFunction(function( text ) {
			text = text.replace( runescape, funescape );
			return function( elem ) {
				return ( elem.textContent || elem.innerText || getText( elem ) ).indexOf( text ) > -1;
			};
		}),

		// "Whether an element is represented by a :lang() selector
		// is based solely on the element's language value
		// being equal to the identifier C,
		// or beginning with the identifier C immediately followed by "-".
		// The matching of C against the element's language value is performed case-insensitively.
		// The identifier C does not have to be a valid language name."
		// http://www.w3.org/TR/selectors/#lang-pseudo
		"lang": markFunction( function( lang ) {
			// lang value must be a valid identifier
			if ( !ridentifier.test(lang || "") ) {
				Sizzle.error( "unsupported lang: " + lang );
			}
			lang = lang.replace( runescape, funescape ).toLowerCase();
			return function( elem ) {
				var elemLang;
				do {
					if ( (elemLang = documentIsHTML ?
						elem.lang :
						elem.getAttribute("xml:lang") || elem.getAttribute("lang")) ) {

						elemLang = elemLang.toLowerCase();
						return elemLang === lang || elemLang.indexOf( lang + "-" ) === 0;
					}
				} while ( (elem = elem.parentNode) && elem.nodeType === 1 );
				return false;
			};
		}),

		// Miscellaneous
		"target": function( elem ) {
			var hash = window.location && window.location.hash;
			return hash && hash.slice( 1 ) === elem.id;
		},

		"root": function( elem ) {
			return elem === docElem;
		},

		"focus": function( elem ) {
			return elem === document.activeElement && (!document.hasFocus || document.hasFocus()) && !!(elem.type || elem.href || ~elem.tabIndex);
		},

		// Boolean properties
		"enabled": function( elem ) {
			return elem.disabled === false;
		},

		"disabled": function( elem ) {
			return elem.disabled === true;
		},

		"checked": function( elem ) {
			// In CSS3, :checked should return both checked and selected elements
			// http://www.w3.org/TR/2011/REC-css3-selectors-20110929/#checked
			var nodeName = elem.nodeName.toLowerCase();
			return (nodeName === "input" && !!elem.checked) || (nodeName === "option" && !!elem.selected);
		},

		"selected": function( elem ) {
			// Accessing this property makes selected-by-default
			// options in Safari work properly
			if ( elem.parentNode ) {
				elem.parentNode.selectedIndex;
			}

			return elem.selected === true;
		},

		// Contents
		"empty": function( elem ) {
			// http://www.w3.org/TR/selectors/#empty-pseudo
			// :empty is negated by element (1) or content nodes (text: 3; cdata: 4; entity ref: 5),
			//   but not by others (comment: 8; processing instruction: 7; etc.)
			// nodeType < 6 works because attributes (2) do not appear as children
			for ( elem = elem.firstChild; elem; elem = elem.nextSibling ) {
				if ( elem.nodeType < 6 ) {
					return false;
				}
			}
			return true;
		},

		"parent": function( elem ) {
			return !Expr.pseudos["empty"]( elem );
		},

		// Element/input types
		"header": function( elem ) {
			return rheader.test( elem.nodeName );
		},

		"input": function( elem ) {
			return rinputs.test( elem.nodeName );
		},

		"button": function( elem ) {
			var name = elem.nodeName.toLowerCase();
			return name === "input" && elem.type === "button" || name === "button";
		},

		"text": function( elem ) {
			var attr;
			return elem.nodeName.toLowerCase() === "input" &&
				elem.type === "text" &&

				// Support: IE<8
				// New HTML5 attribute values (e.g., "search") appear with elem.type === "text"
				( (attr = elem.getAttribute("type")) == null || attr.toLowerCase() === "text" );
		},

		// Position-in-collection
		"first": createPositionalPseudo(function() {
			return [ 0 ];
		}),

		"last": createPositionalPseudo(function( matchIndexes, length ) {
			return [ length - 1 ];
		}),

		"eq": createPositionalPseudo(function( matchIndexes, length, argument ) {
			return [ argument < 0 ? argument + length : argument ];
		}),

		"even": createPositionalPseudo(function( matchIndexes, length ) {
			var i = 0;
			for ( ; i < length; i += 2 ) {
				matchIndexes.push( i );
			}
			return matchIndexes;
		}),

		"odd": createPositionalPseudo(function( matchIndexes, length ) {
			var i = 1;
			for ( ; i < length; i += 2 ) {
				matchIndexes.push( i );
			}
			return matchIndexes;
		}),

		"lt": createPositionalPseudo(function( matchIndexes, length, argument ) {
			var i = argument < 0 ? argument + length : argument;
			for ( ; --i >= 0; ) {
				matchIndexes.push( i );
			}
			return matchIndexes;
		}),

		"gt": createPositionalPseudo(function( matchIndexes, length, argument ) {
			var i = argument < 0 ? argument + length : argument;
			for ( ; ++i < length; ) {
				matchIndexes.push( i );
			}
			return matchIndexes;
		})
	}
};

Expr.pseudos["nth"] = Expr.pseudos["eq"];

// Add button/input type pseudos
for ( i in { radio: true, checkbox: true, file: true, password: true, image: true } ) {
	Expr.pseudos[ i ] = createInputPseudo( i );
}
for ( i in { submit: true, reset: true } ) {
	Expr.pseudos[ i ] = createButtonPseudo( i );
}

// Easy API for creating new setFilters
function setFilters() {}
setFilters.prototype = Expr.filters = Expr.pseudos;
Expr.setFilters = new setFilters();

tokenize = Sizzle.tokenize = function( selector, parseOnly ) {
	var matched, match, tokens, type,
		soFar, groups, preFilters,
		cached = tokenCache[ selector + " " ];

	if ( cached ) {
		return parseOnly ? 0 : cached.slice( 0 );
	}

	soFar = selector;
	groups = [];
	preFilters = Expr.preFilter;

	while ( soFar ) {

		// Comma and first run
		if ( !matched || (match = rcomma.exec( soFar )) ) {
			if ( match ) {
				// Don't consume trailing commas as valid
				soFar = soFar.slice( match[0].length ) || soFar;
			}
			groups.push( (tokens = []) );
		}

		matched = false;

		// Combinators
		if ( (match = rcombinators.exec( soFar )) ) {
			matched = match.shift();
			tokens.push({
				value: matched,
				// Cast descendant combinators to space
				type: match[0].replace( rtrim, " " )
			});
			soFar = soFar.slice( matched.length );
		}

		// Filters
		for ( type in Expr.filter ) {
			if ( (match = matchExpr[ type ].exec( soFar )) && (!preFilters[ type ] ||
				(match = preFilters[ type ]( match ))) ) {
				matched = match.shift();
				tokens.push({
					value: matched,
					type: type,
					matches: match
				});
				soFar = soFar.slice( matched.length );
			}
		}

		if ( !matched ) {
			break;
		}
	}

	// Return the length of the invalid excess
	// if we're just parsing
	// Otherwise, throw an error or return tokens
	return parseOnly ?
		soFar.length :
		soFar ?
			Sizzle.error( selector ) :
			// Cache the tokens
			tokenCache( selector, groups ).slice( 0 );
};

function toSelector( tokens ) {
	var i = 0,
		len = tokens.length,
		selector = "";
	for ( ; i < len; i++ ) {
		selector += tokens[i].value;
	}
	return selector;
}

function addCombinator( matcher, combinator, base ) {
	var dir = combinator.dir,
		checkNonElements = base && dir === "parentNode",
		doneName = done++;

	return combinator.first ?
		// Check against closest ancestor/preceding element
		function( elem, context, xml ) {
			while ( (elem = elem[ dir ]) ) {
				if ( elem.nodeType === 1 || checkNonElements ) {
					return matcher( elem, context, xml );
				}
			}
		} :

		// Check against all ancestor/preceding elements
		function( elem, context, xml ) {
			var oldCache, outerCache,
				newCache = [ dirruns, doneName ];

			// We can't set arbitrary data on XML nodes, so they don't benefit from dir caching
			if ( xml ) {
				while ( (elem = elem[ dir ]) ) {
					if ( elem.nodeType === 1 || checkNonElements ) {
						if ( matcher( elem, context, xml ) ) {
							return true;
						}
					}
				}
			} else {
				while ( (elem = elem[ dir ]) ) {
					if ( elem.nodeType === 1 || checkNonElements ) {
						outerCache = elem[ expando ] || (elem[ expando ] = {});
						if ( (oldCache = outerCache[ dir ]) &&
							oldCache[ 0 ] === dirruns && oldCache[ 1 ] === doneName ) {

							// Assign to newCache so results back-propagate to previous elements
							return (newCache[ 2 ] = oldCache[ 2 ]);
						} else {
							// Reuse newcache so results back-propagate to previous elements
							outerCache[ dir ] = newCache;

							// A match means we're done; a fail means we have to keep checking
							if ( (newCache[ 2 ] = matcher( elem, context, xml )) ) {
								return true;
							}
						}
					}
				}
			}
		};
}

function elementMatcher( matchers ) {
	return matchers.length > 1 ?
		function( elem, context, xml ) {
			var i = matchers.length;
			while ( i-- ) {
				if ( !matchers[i]( elem, context, xml ) ) {
					return false;
				}
			}
			return true;
		} :
		matchers[0];
}

function multipleContexts( selector, contexts, results ) {
	var i = 0,
		len = contexts.length;
	for ( ; i < len; i++ ) {
		Sizzle( selector, contexts[i], results );
	}
	return results;
}

function condense( unmatched, map, filter, context, xml ) {
	var elem,
		newUnmatched = [],
		i = 0,
		len = unmatched.length,
		mapped = map != null;

	for ( ; i < len; i++ ) {
		if ( (elem = unmatched[i]) ) {
			if ( !filter || filter( elem, context, xml ) ) {
				newUnmatched.push( elem );
				if ( mapped ) {
					map.push( i );
				}
			}
		}
	}

	return newUnmatched;
}

function setMatcher( preFilter, selector, matcher, postFilter, postFinder, postSelector ) {
	if ( postFilter && !postFilter[ expando ] ) {
		postFilter = setMatcher( postFilter );
	}
	if ( postFinder && !postFinder[ expando ] ) {
		postFinder = setMatcher( postFinder, postSelector );
	}
	return markFunction(function( seed, results, context, xml ) {
		var temp, i, elem,
			preMap = [],
			postMap = [],
			preexisting = results.length,

			// Get initial elements from seed or context
			elems = seed || multipleContexts( selector || "*", context.nodeType ? [ context ] : context, [] ),

			// Prefilter to get matcher input, preserving a map for seed-results synchronization
			matcherIn = preFilter && ( seed || !selector ) ?
				condense( elems, preMap, preFilter, context, xml ) :
				elems,

			matcherOut = matcher ?
				// If we have a postFinder, or filtered seed, or non-seed postFilter or preexisting results,
				postFinder || ( seed ? preFilter : preexisting || postFilter ) ?

					// ...intermediate processing is necessary
					[] :

					// ...otherwise use results directly
					results :
				matcherIn;

		// Find primary matches
		if ( matcher ) {
			matcher( matcherIn, matcherOut, context, xml );
		}

		// Apply postFilter
		if ( postFilter ) {
			temp = condense( matcherOut, postMap );
			postFilter( temp, [], context, xml );

			// Un-match failing elements by moving them back to matcherIn
			i = temp.length;
			while ( i-- ) {
				if ( (elem = temp[i]) ) {
					matcherOut[ postMap[i] ] = !(matcherIn[ postMap[i] ] = elem);
				}
			}
		}

		if ( seed ) {
			if ( postFinder || preFilter ) {
				if ( postFinder ) {
					// Get the final matcherOut by condensing this intermediate into postFinder contexts
					temp = [];
					i = matcherOut.length;
					while ( i-- ) {
						if ( (elem = matcherOut[i]) ) {
							// Restore matcherIn since elem is not yet a final match
							temp.push( (matcherIn[i] = elem) );
						}
					}
					postFinder( null, (matcherOut = []), temp, xml );
				}

				// Move matched elements from seed to results to keep them synchronized
				i = matcherOut.length;
				while ( i-- ) {
					if ( (elem = matcherOut[i]) &&
						(temp = postFinder ? indexOf( seed, elem ) : preMap[i]) > -1 ) {

						seed[temp] = !(results[temp] = elem);
					}
				}
			}

		// Add elements to results, through postFinder if defined
		} else {
			matcherOut = condense(
				matcherOut === results ?
					matcherOut.splice( preexisting, matcherOut.length ) :
					matcherOut
			);
			if ( postFinder ) {
				postFinder( null, results, matcherOut, xml );
			} else {
				push.apply( results, matcherOut );
			}
		}
	});
}

function matcherFromTokens( tokens ) {
	var checkContext, matcher, j,
		len = tokens.length,
		leadingRelative = Expr.relative[ tokens[0].type ],
		implicitRelative = leadingRelative || Expr.relative[" "],
		i = leadingRelative ? 1 : 0,

		// The foundational matcher ensures that elements are reachable from top-level context(s)
		matchContext = addCombinator( function( elem ) {
			return elem === checkContext;
		}, implicitRelative, true ),
		matchAnyContext = addCombinator( function( elem ) {
			return indexOf( checkContext, elem ) > -1;
		}, implicitRelative, true ),
		matchers = [ function( elem, context, xml ) {
			var ret = ( !leadingRelative && ( xml || context !== outermostContext ) ) || (
				(checkContext = context).nodeType ?
					matchContext( elem, context, xml ) :
					matchAnyContext( elem, context, xml ) );
			// Avoid hanging onto element (issue #299)
			checkContext = null;
			return ret;
		} ];

	for ( ; i < len; i++ ) {
		if ( (matcher = Expr.relative[ tokens[i].type ]) ) {
			matchers = [ addCombinator(elementMatcher( matchers ), matcher) ];
		} else {
			matcher = Expr.filter[ tokens[i].type ].apply( null, tokens[i].matches );

			// Return special upon seeing a positional matcher
			if ( matcher[ expando ] ) {
				// Find the next relative operator (if any) for proper handling
				j = ++i;
				for ( ; j < len; j++ ) {
					if ( Expr.relative[ tokens[j].type ] ) {
						break;
					}
				}
				return setMatcher(
					i > 1 && elementMatcher( matchers ),
					i > 1 && toSelector(
						// If the preceding token was a descendant combinator, insert an implicit any-element `*`
						tokens.slice( 0, i - 1 ).concat({ value: tokens[ i - 2 ].type === " " ? "*" : "" })
					).replace( rtrim, "$1" ),
					matcher,
					i < j && matcherFromTokens( tokens.slice( i, j ) ),
					j < len && matcherFromTokens( (tokens = tokens.slice( j )) ),
					j < len && toSelector( tokens )
				);
			}
			matchers.push( matcher );
		}
	}

	return elementMatcher( matchers );
}

function matcherFromGroupMatchers( elementMatchers, setMatchers ) {
	var bySet = setMatchers.length > 0,
		byElement = elementMatchers.length > 0,
		superMatcher = function( seed, context, xml, results, outermost ) {
			var elem, j, matcher,
				matchedCount = 0,
				i = "0",
				unmatched = seed && [],
				setMatched = [],
				contextBackup = outermostContext,
				// We must always have either seed elements or outermost context
				elems = seed || byElement && Expr.find["TAG"]( "*", outermost ),
				// Use integer dirruns iff this is the outermost matcher
				dirrunsUnique = (dirruns += contextBackup == null ? 1 : Math.random() || 0.1),
				len = elems.length;

			if ( outermost ) {
				outermostContext = context !== document && context;
			}

			// Add elements passing elementMatchers directly to results
			// Keep `i` a string if there are no elements so `matchedCount` will be "00" below
			// Support: IE<9, Safari
			// Tolerate NodeList properties (IE: "length"; Safari: <number>) matching elements by id
			for ( ; i !== len && (elem = elems[i]) != null; i++ ) {
				if ( byElement && elem ) {
					j = 0;
					while ( (matcher = elementMatchers[j++]) ) {
						if ( matcher( elem, context, xml ) ) {
							results.push( elem );
							break;
						}
					}
					if ( outermost ) {
						dirruns = dirrunsUnique;
					}
				}

				// Track unmatched elements for set filters
				if ( bySet ) {
					// They will have gone through all possible matchers
					if ( (elem = !matcher && elem) ) {
						matchedCount--;
					}

					// Lengthen the array for every element, matched or not
					if ( seed ) {
						unmatched.push( elem );
					}
				}
			}

			// Apply set filters to unmatched elements
			matchedCount += i;
			if ( bySet && i !== matchedCount ) {
				j = 0;
				while ( (matcher = setMatchers[j++]) ) {
					matcher( unmatched, setMatched, context, xml );
				}

				if ( seed ) {
					// Reintegrate element matches to eliminate the need for sorting
					if ( matchedCount > 0 ) {
						while ( i-- ) {
							if ( !(unmatched[i] || setMatched[i]) ) {
								setMatched[i] = pop.call( results );
							}
						}
					}

					// Discard index placeholder values to get only actual matches
					setMatched = condense( setMatched );
				}

				// Add matches to results
				push.apply( results, setMatched );

				// Seedless set matches succeeding multiple successful matchers stipulate sorting
				if ( outermost && !seed && setMatched.length > 0 &&
					( matchedCount + setMatchers.length ) > 1 ) {

					Sizzle.uniqueSort( results );
				}
			}

			// Override manipulation of globals by nested matchers
			if ( outermost ) {
				dirruns = dirrunsUnique;
				outermostContext = contextBackup;
			}

			return unmatched;
		};

	return bySet ?
		markFunction( superMatcher ) :
		superMatcher;
}

compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) {
	var i,
		setMatchers = [],
		elementMatchers = [],
		cached = compilerCache[ selector + " " ];

	if ( !cached ) {
		// Generate a function of recursive functions that can be used to check each element
		if ( !match ) {
			match = tokenize( selector );
		}
		i = match.length;
		while ( i-- ) {
			cached = matcherFromTokens( match[i] );
			if ( cached[ expando ] ) {
				setMatchers.push( cached );
			} else {
				elementMatchers.push( cached );
			}
		}

		// Cache the compiled function
		cached = compilerCache( selector, matcherFromGroupMatchers( elementMatchers, setMatchers ) );

		// Save selector and tokenization
		cached.selector = selector;
	}
	return cached;
};

/**
 * A low-level selection function that works with Sizzle's compiled
 *  selector functions
 * @param {String|Function} selector A selector or a pre-compiled
 *  selector function built with Sizzle.compile
 * @param {Element} context
 * @param {Array} [results]
 * @param {Array} [seed] A set of elements to match against
 */
select = Sizzle.select = function( selector, context, results, seed ) {
	var i, tokens, token, type, find,
		compiled = typeof selector === "function" && selector,
		match = !seed && tokenize( (selector = compiled.selector || selector) );

	results = results || [];

	// Try to minimize operations if there is no seed and only one group
	if ( match.length === 1 ) {

		// Take a shortcut and set the context if the root selector is an ID
		tokens = match[0] = match[0].slice( 0 );
		if ( tokens.length > 2 && (token = tokens[0]).type === "ID" &&
				support.getById && context.nodeType === 9 && documentIsHTML &&
				Expr.relative[ tokens[1].type ] ) {

			context = ( Expr.find["ID"]( token.matches[0].replace(runescape, funescape), context ) || [] )[0];
			if ( !context ) {
				return results;

			// Precompiled matchers will still verify ancestry, so step up a level
			} else if ( compiled ) {
				context = context.parentNode;
			}

			selector = selector.slice( tokens.shift().value.length );
		}

		// Fetch a seed set for right-to-left matching
		i = matchExpr["needsContext"].test( selector ) ? 0 : tokens.length;
		while ( i-- ) {
			token = tokens[i];

			// Abort if we hit a combinator
			if ( Expr.relative[ (type = token.type) ] ) {
				break;
			}
			if ( (find = Expr.find[ type ]) ) {
				// Search, expanding context for leading sibling combinators
				if ( (seed = find(
					token.matches[0].replace( runescape, funescape ),
					rsibling.test( tokens[0].type ) && testContext( context.parentNode ) || context
				)) ) {

					// If seed is empty or no tokens remain, we can return early
					tokens.splice( i, 1 );
					selector = seed.length && toSelector( tokens );
					if ( !selector ) {
						push.apply( results, seed );
						return results;
					}

					break;
				}
			}
		}
	}

	// Compile and execute a filtering function if one is not provided
	// Provide `match` to avoid retokenization if we modified the selector above
	( compiled || compile( selector, match ) )(
		seed,
		context,
		!documentIsHTML,
		results,
		rsibling.test( selector ) && testContext( context.parentNode ) || context
	);
	return results;
};

// One-time assignments

// Sort stability
support.sortStable = expando.split("").sort( sortOrder ).join("") === expando;

// Support: Chrome 14-35+
// Always assume duplicates if they aren't passed to the comparison function
support.detectDuplicates = !!hasDuplicate;

// Initialize against the default document
setDocument();

// Support: Webkit<537.32 - Safari 6.0.3/Chrome 25 (fixed in Chrome 27)
// Detached nodes confoundingly follow *each other*
support.sortDetached = assert(function( div1 ) {
	// Should return 1, but returns 4 (following)
	return div1.compareDocumentPosition( document.createElement("div") ) & 1;
});

// Support: IE<8
// Prevent attribute/property "interpolation"
// http://msdn.microsoft.com/en-us/library/ms536429%28VS.85%29.aspx
if ( !assert(function( div ) {
	div.innerHTML = "<a href='#'></a>";
	return div.firstChild.getAttribute("href") === "#" ;
}) ) {
	addHandle( "type|href|height|width", function( elem, name, isXML ) {
		if ( !isXML ) {
			return elem.getAttribute( name, name.toLowerCase() === "type" ? 1 : 2 );
		}
	});
}

// Support: IE<9
// Use defaultValue in place of getAttribute("value")
if ( !support.attributes || !assert(function( div ) {
	div.innerHTML = "<input/>";
	div.firstChild.setAttribute( "value", "" );
	return div.firstChild.getAttribute( "value" ) === "";
}) ) {
	addHandle( "value", function( elem, name, isXML ) {
		if ( !isXML && elem.nodeName.toLowerCase() === "input" ) {
			return elem.defaultValue;
		}
	});
}

// Support: IE<9
// Use getAttributeNode to fetch booleans when getAttribute lies
if ( !assert(function( div ) {
	return div.getAttribute("disabled") == null;
}) ) {
	addHandle( booleans, function( elem, name, isXML ) {
		var val;
		if ( !isXML ) {
			return elem[ name ] === true ? name.toLowerCase() :
					(val = elem.getAttributeNode( name )) && val.specified ?
					val.value :
				null;
		}
	});
}

return Sizzle;

})( window );



jQuery.find = Sizzle;
jQuery.expr = Sizzle.selectors;
jQuery.expr[":"] = jQuery.expr.pseudos;
jQuery.unique = Sizzle.uniqueSort;
jQuery.text = Sizzle.getText;
jQuery.isXMLDoc = Sizzle.isXML;
jQuery.contains = Sizzle.contains;



var rneedsContext = jQuery.expr.match.needsContext;

var rsingleTag = (/^<(\w+)\s*\/?>(?:<\/\1>|)$/);



var risSimple = /^.[^:#\[\.,]*$/;

// Implement the identical functionality for filter and not
function winnow( elements, qualifier, not ) {
	if ( jQuery.isFunction( qualifier ) ) {
		return jQuery.grep( elements, function( elem, i ) {
			/* jshint -W018 */
			return !!qualifier.call( elem, i, elem ) !== not;
		});

	}

	if ( qualifier.nodeType ) {
		return jQuery.grep( elements, function( elem ) {
			return ( elem === qualifier ) !== not;
		});

	}

	if ( typeof qualifier === "string" ) {
		if ( risSimple.test( qualifier ) ) {
			return jQuery.filter( qualifier, elements, not );
		}

		qualifier = jQuery.filter( qualifier, elements );
	}

	return jQuery.grep( elements, function( elem ) {
		return ( jQuery.inArray( elem, qualifier ) >= 0 ) !== not;
	});
}

jQuery.filter = function( expr, elems, not ) {
	var elem = elems[ 0 ];

	if ( not ) {
		expr = ":not(" + expr + ")";
	}

	return elems.length === 1 && elem.nodeType === 1 ?
		jQuery.find.matchesSelector( elem, expr ) ? [ elem ] : [] :
		jQuery.find.matches( expr, jQuery.grep( elems, function( elem ) {
			return elem.nodeType === 1;
		}));
};

jQuery.fn.extend({
	find: function( selector ) {
		var i,
			ret = [],
			self = this,
			len = self.length;

		if ( typeof selector !== "string" ) {
			return this.pushStack( jQuery( selector ).filter(function() {
				for ( i = 0; i < len; i++ ) {
					if ( jQuery.contains( self[ i ], this ) ) {
						return true;
					}
				}
			}) );
		}

		for ( i = 0; i < len; i++ ) {
			jQuery.find( selector, self[ i ], ret );
		}

		// Needed because $( selector, context ) becomes $( context ).find( selector )
		ret = this.pushStack( len > 1 ? jQuery.unique( ret ) : ret );
		ret.selector = this.selector ? this.selector + " " + selector : selector;
		return ret;
	},
	filter: function( selector ) {
		return this.pushStack( winnow(this, selector || [], false) );
	},
	not: function( selector ) {
		return this.pushStack( winnow(this, selector || [], true) );
	},
	is: function( selector ) {
		return !!winnow(
			this,

			// If this is a positional/relative selector, check membership in the returned set
			// so $("p:first").is("p:last") won't return true for a doc with two "p".
			typeof selector === "string" && rneedsContext.test( selector ) ?
				jQuery( selector ) :
				selector || [],
			false
		).length;
	}
});


// Initialize a jQuery object


// A central reference to the root jQuery(document)
var rootjQuery,

	// Use the correct document accordingly with window argument (sandbox)
	document = window.document,

	// A simple way to check for HTML strings
	// Prioritize #id over <tag> to avoid XSS via location.hash (#9521)
	// Strict HTML recognition (#11290: must start with <)
	rquickExpr = /^(?:\s*(<[\w\W]+>)[^>]*|#([\w-]*))$/,

	init = jQuery.fn.init = function( selector, context ) {
		var match, elem;

		// HANDLE: $(""), $(null), $(undefined), $(false)
		if ( !selector ) {
			return this;
		}

		// Handle HTML strings
		if ( typeof selector === "string" ) {
			if ( selector.charAt(0) === "<" && selector.charAt( selector.length - 1 ) === ">" && selector.length >= 3 ) {
				// Assume that strings that start and end with <> are HTML and skip the regex check
				match = [ null, selector, null ];

			} else {
				match = rquickExpr.exec( selector );
			}

			// Match html or make sure no context is specified for #id
			if ( match && (match[1] || !context) ) {

				// HANDLE: $(html) -> $(array)
				if ( match[1] ) {
					context = context instanceof jQuery ? context[0] : context;

					// scripts is true for back-compat
					// Intentionally let the error be thrown if parseHTML is not present
					jQuery.merge( this, jQuery.parseHTML(
						match[1],
						context && context.nodeType ? context.ownerDocument || context : document,
						true
					) );

					// HANDLE: $(html, props)
					if ( rsingleTag.test( match[1] ) && jQuery.isPlainObject( context ) ) {
						for ( match in context ) {
							// Properties of context are called as methods if possible
							if ( jQuery.isFunction( this[ match ] ) ) {
								this[ match ]( context[ match ] );

							// ...and otherwise set as attributes
							} else {
								this.attr( match, context[ match ] );
							}
						}
					}

					return this;

				// HANDLE: $(#id)
				} else {
					elem = document.getElementById( match[2] );

					// Check parentNode to catch when Blackberry 4.6 returns
					// nodes that are no longer in the document #6963
					if ( elem && elem.parentNode ) {
						// Handle the case where IE and Opera return items
						// by name instead of ID
						if ( elem.id !== match[2] ) {
							return rootjQuery.find( selector );
						}

						// Otherwise, we inject the element directly into the jQuery object
						this.length = 1;
						this[0] = elem;
					}

					this.context = document;
					this.selector = selector;
					return this;
				}

			// HANDLE: $(expr, $(...))
			} else if ( !context || context.jquery ) {
				return ( context || rootjQuery ).find( selector );

			// HANDLE: $(expr, context)
			// (which is just equivalent to: $(context).find(expr)
			} else {
				return this.constructor( context ).find( selector );
			}

		// HANDLE: $(DOMElement)
		} else if ( selector.nodeType ) {
			this.context = this[0] = selector;
			this.length = 1;
			return this;

		// HANDLE: $(function)
		// Shortcut for document ready
		} else if ( jQuery.isFunction( selector ) ) {
			return typeof rootjQuery.ready !== "undefined" ?
				rootjQuery.ready( selector ) :
				// Execute immediately if ready is not present
				selector( jQuery );
		}

		if ( selector.selector !== undefined ) {
			this.selector = selector.selector;
			this.context = selector.context;
		}

		return jQuery.makeArray( selector, this );
	};

// Give the init function the jQuery prototype for later instantiation
init.prototype = jQuery.fn;

// Initialize central reference
rootjQuery = jQuery( document );


var rparentsprev = /^(?:parents|prev(?:Until|All))/,
	// methods guaranteed to produce a unique set when starting from a unique set
	guaranteedUnique = {
		children: true,
		contents: true,
		next: true,
		prev: true
	};

jQuery.extend({
	dir: function( elem, dir, until ) {
		var matched = [],
			cur = elem[ dir ];

		while ( cur && cur.nodeType !== 9 && (until === undefined || cur.nodeType !== 1 || !jQuery( cur ).is( until )) ) {
			if ( cur.nodeType === 1 ) {
				matched.push( cur );
			}
			cur = cur[dir];
		}
		return matched;
	},

	sibling: function( n, elem ) {
		var r = [];

		for ( ; n; n = n.nextSibling ) {
			if ( n.nodeType === 1 && n !== elem ) {
				r.push( n );
			}
		}

		return r;
	}
});

jQuery.fn.extend({
	has: function( target ) {
		var i,
			targets = jQuery( target, this ),
			len = targets.length;

		return this.filter(function() {
			for ( i = 0; i < len; i++ ) {
				if ( jQuery.contains( this, targets[i] ) ) {
					return true;
				}
			}
		});
	},

	closest: function( selectors, context ) {
		var cur,
			i = 0,
			l = this.length,
			matched = [],
			pos = rneedsContext.test( selectors ) || typeof selectors !== "string" ?
				jQuery( selectors, context || this.context ) :
				0;

		for ( ; i < l; i++ ) {
			for ( cur = this[i]; cur && cur !== context; cur = cur.parentNode ) {
				// Always skip document fragments
				if ( cur.nodeType < 11 && (pos ?
					pos.index(cur) > -1 :

					// Don't pass non-elements to Sizzle
					cur.nodeType === 1 &&
						jQuery.find.matchesSelector(cur, selectors)) ) {

					matched.push( cur );
					break;
				}
			}
		}

		return this.pushStack( matched.length > 1 ? jQuery.unique( matched ) : matched );
	},

	// Determine the position of an element within
	// the matched set of elements
	index: function( elem ) {

		// No argument, return index in parent
		if ( !elem ) {
			return ( this[0] && this[0].parentNode ) ? this.first().prevAll().length : -1;
		}

		// index in selector
		if ( typeof elem === "string" ) {
			return jQuery.inArray( this[0], jQuery( elem ) );
		}

		// Locate the position of the desired element
		return jQuery.inArray(
			// If it receives a jQuery object, the first element is used
			elem.jquery ? elem[0] : elem, this );
	},

	add: function( selector, context ) {
		return this.pushStack(
			jQuery.unique(
				jQuery.merge( this.get(), jQuery( selector, context ) )
			)
		);
	},

	addBack: function( selector ) {
		return this.add( selector == null ?
			this.prevObject : this.prevObject.filter(selector)
		);
	}
});

function sibling( cur, dir ) {
	do {
		cur = cur[ dir ];
	} while ( cur && cur.nodeType !== 1 );

	return cur;
}

jQuery.each({
	parent: function( elem ) {
		var parent = elem.parentNode;
		return parent && parent.nodeType !== 11 ? parent : null;
	},
	parents: function( elem ) {
		return jQuery.dir( elem, "parentNode" );
	},
	parentsUntil: function( elem, i, until ) {
		return jQuery.dir( elem, "parentNode", until );
	},
	next: function( elem ) {
		return sibling( elem, "nextSibling" );
	},
	prev: function( elem ) {
		return sibling( elem, "previousSibling" );
	},
	nextAll: function( elem ) {
		return jQuery.dir( elem, "nextSibling" );
	},
	prevAll: function( elem ) {
		return jQuery.dir( elem, "previousSibling" );
	},
	nextUntil: function( elem, i, until ) {
		return jQuery.dir( elem, "nextSibling", until );
	},
	prevUntil: function( elem, i, until ) {
		return jQuery.dir( elem, "previousSibling", until );
	},
	siblings: function( elem ) {
		return jQuery.sibling( ( elem.parentNode || {} ).firstChild, elem );
	},
	children: function( elem ) {
		return jQuery.sibling( elem.firstChild );
	},
	contents: function( elem ) {
		return jQuery.nodeName( elem, "iframe" ) ?
			elem.contentDocument || elem.contentWindow.document :
			jQuery.merge( [], elem.childNodes );
	}
}, function( name, fn ) {
	jQuery.fn[ name ] = function( until, selector ) {
		var ret = jQuery.map( this, fn, until );

		if ( name.slice( -5 ) !== "Until" ) {
			selector = until;
		}

		if ( selector && typeof selector === "string" ) {
			ret = jQuery.filter( selector, ret );
		}

		if ( this.length > 1 ) {
			// Remove duplicates
			if ( !guaranteedUnique[ name ] ) {
				ret = jQuery.unique( ret );
			}

			// Reverse order for parents* and prev-derivatives
			if ( rparentsprev.test( name ) ) {
				ret = ret.reverse();
			}
		}

		return this.pushStack( ret );
	};
});
var rnotwhite = (/\S+/g);



// String to Object options format cache
var optionsCache = {};

// Convert String-formatted options into Object-formatted ones and store in cache
function createOptions( options ) {
	var object = optionsCache[ options ] = {};
	jQuery.each( options.match( rnotwhite ) || [], function( _, flag ) {
		object[ flag ] = true;
	});
	return object;
}

/*
 * Create a callback list using the following parameters:
 *
 *	options: an optional list of space-separated options that will change how
 *			the callback list behaves or a more traditional option object
 *
 * By default a callback list will act like an event callback list and can be
 * "fired" multiple times.
 *
 * Possible options:
 *
 *	once:			will ensure the callback list can only be fired once (like a Deferred)
 *
 *	memory:			will keep track of previous values and will call any callback added
 *					after the list has been fired right away with the latest "memorized"
 *					values (like a Deferred)
 *
 *	unique:			will ensure a callback can only be added once (no duplicate in the list)
 *
 *	stopOnFalse:	interrupt callings when a callback returns false
 *
 */
jQuery.Callbacks = function( options ) {

	// Convert options from String-formatted to Object-formatted if needed
	// (we check in cache first)
	options = typeof options === "string" ?
		( optionsCache[ options ] || createOptions( options ) ) :
		jQuery.extend( {}, options );

	var // Flag to know if list is currently firing
		firing,
		// Last fire value (for non-forgettable lists)
		memory,
		// Flag to know if list was already fired
		fired,
		// End of the loop when firing
		firingLength,
		// Index of currently firing callback (modified by remove if needed)
		firingIndex,
		// First callback to fire (used internally by add and fireWith)
		firingStart,
		// Actual callback list
		list = [],
		// Stack of fire calls for repeatable lists
		stack = !options.once && [],
		// Fire callbacks
		fire = function( data ) {
			memory = options.memory && data;
			fired = true;
			firingIndex = firingStart || 0;
			firingStart = 0;
			firingLength = list.length;
			firing = true;
			for ( ; list && firingIndex < firingLength; firingIndex++ ) {
				if ( list[ firingIndex ].apply( data[ 0 ], data[ 1 ] ) === false && options.stopOnFalse ) {
					memory = false; // To prevent further calls using add
					break;
				}
			}
			firing = false;
			if ( list ) {
				if ( stack ) {
					if ( stack.length ) {
						fire( stack.shift() );
					}
				} else if ( memory ) {
					list = [];
				} else {
					self.disable();
				}
			}
		},
		// Actual Callbacks object
		self = {
			// Add a callback or a collection of callbacks to the list
			add: function() {
				if ( list ) {
					// First, we save the current length
					var start = list.length;
					(function add( args ) {
						jQuery.each( args, function( _, arg ) {
							var type = jQuery.type( arg );
							if ( type === "function" ) {
								if ( !options.unique || !self.has( arg ) ) {
									list.push( arg );
								}
							} else if ( arg && arg.length && type !== "string" ) {
								// Inspect recursively
								add( arg );
							}
						});
					})( arguments );
					// Do we need to add the callbacks to the
					// current firing batch?
					if ( firing ) {
						firingLength = list.length;
					// With memory, if we're not firing then
					// we should call right away
					} else if ( memory ) {
						firingStart = start;
						fire( memory );
					}
				}
				return this;
			},
			// Remove a callback from the list
			remove: function() {
				if ( list ) {
					jQuery.each( arguments, function( _, arg ) {
						var index;
						while ( ( index = jQuery.inArray( arg, list, index ) ) > -1 ) {
							list.splice( index, 1 );
							// Handle firing indexes
							if ( firing ) {
								if ( index <= firingLength ) {
									firingLength--;
								}
								if ( index <= firingIndex ) {
									firingIndex--;
								}
							}
						}
					});
				}
				return this;
			},
			// Check if a given callback is in the list.
			// If no argument is given, return whether or not list has callbacks attached.
			has: function( fn ) {
				return fn ? jQuery.inArray( fn, list ) > -1 : !!( list && list.length );
			},
			// Remove all callbacks from the list
			empty: function() {
				list = [];
				firingLength = 0;
				return this;
			},
			// Have the list do nothing anymore
			disable: function() {
				list = stack = memory = undefined;
				return this;
			},
			// Is it disabled?
			disabled: function() {
				return !list;
			},
			// Lock the list in its current state
			lock: function() {
				stack = undefined;
				if ( !memory ) {
					self.disable();
				}
				return this;
			},
			// Is it locked?
			locked: function() {
				return !stack;
			},
			// Call all callbacks with the given context and arguments
			fireWith: function( context, args ) {
				if ( list && ( !fired || stack ) ) {
					args = args || [];
					args = [ context, args.slice ? args.slice() : args ];
					if ( firing ) {
						stack.push( args );
					} else {
						fire( args );
					}
				}
				return this;
			},
			// Call all the callbacks with the given arguments
			fire: function() {
				self.fireWith( this, arguments );
				return this;
			},
			// To know if the callbacks have already been called at least once
			fired: function() {
				return !!fired;
			}
		};

	return self;
};


jQuery.extend({

	Deferred: function( func ) {
		var tuples = [
				// action, add listener, listener list, final state
				[ "resolve", "done", jQuery.Callbacks("once memory"), "resolved" ],
				[ "reject", "fail", jQuery.Callbacks("once memory"), "rejected" ],
				[ "notify", "progress", jQuery.Callbacks("memory") ]
			],
			state = "pending",
			promise = {
				state: function() {
					return state;
				},
				always: function() {
					deferred.done( arguments ).fail( arguments );
					return this;
				},
				then: function( /* fnDone, fnFail, fnProgress */ ) {
					var fns = arguments;
					return jQuery.Deferred(function( newDefer ) {
						jQuery.each( tuples, function( i, tuple ) {
							var fn = jQuery.isFunction( fns[ i ] ) && fns[ i ];
							// deferred[ done | fail | progress ] for forwarding actions to newDefer
							deferred[ tuple[1] ](function() {
								var returned = fn && fn.apply( this, arguments );
								if ( returned && jQuery.isFunction( returned.promise ) ) {
									returned.promise()
										.done( newDefer.resolve )
										.fail( newDefer.reject )
										.progress( newDefer.notify );
								} else {
									newDefer[ tuple[ 0 ] + "With" ]( this === promise ? newDefer.promise() : this, fn ? [ returned ] : arguments );
								}
							});
						});
						fns = null;
					}).promise();
				},
				// Get a promise for this deferred
				// If obj is provided, the promise aspect is added to the object
				promise: function( obj ) {
					return obj != null ? jQuery.extend( obj, promise ) : promise;
				}
			},
			deferred = {};

		// Keep pipe for back-compat
		promise.pipe = promise.then;

		// Add list-specific methods
		jQuery.each( tuples, function( i, tuple ) {
			var list = tuple[ 2 ],
				stateString = tuple[ 3 ];

			// promise[ done | fail | progress ] = list.add
			promise[ tuple[1] ] = list.add;

			// Handle state
			if ( stateString ) {
				list.add(function() {
					// state = [ resolved | rejected ]
					state = stateString;

				// [ reject_list | resolve_list ].disable; progress_list.lock
				}, tuples[ i ^ 1 ][ 2 ].disable, tuples[ 2 ][ 2 ].lock );
			}

			// deferred[ resolve | reject | notify ]
			deferred[ tuple[0] ] = function() {
				deferred[ tuple[0] + "With" ]( this === deferred ? promise : this, arguments );
				return this;
			};
			deferred[ tuple[0] + "With" ] = list.fireWith;
		});

		// Make the deferred a promise
		promise.promise( deferred );

		// Call given func if any
		if ( func ) {
			func.call( deferred, deferred );
		}

		// All done!
		return deferred;
	},

	// Deferred helper
	when: function( subordinate /* , ..., subordinateN */ ) {
		var i = 0,
			resolveValues = slice.call( arguments ),
			length = resolveValues.length,

			// the count of uncompleted subordinates
			remaining = length !== 1 || ( subordinate && jQuery.isFunction( subordinate.promise ) ) ? length : 0,

			// the master Deferred. If resolveValues consist of only a single Deferred, just use that.
			deferred = remaining === 1 ? subordinate : jQuery.Deferred(),

			// Update function for both resolve and progress values
			updateFunc = function( i, contexts, values ) {
				return function( value ) {
					contexts[ i ] = this;
					values[ i ] = arguments.length > 1 ? slice.call( arguments ) : value;
					if ( values === progressValues ) {
						deferred.notifyWith( contexts, values );

					} else if ( !(--remaining) ) {
						deferred.resolveWith( contexts, values );
					}
				};
			},

			progressValues, progressContexts, resolveContexts;

		// add listeners to Deferred subordinates; treat others as resolved
		if ( length > 1 ) {
			progressValues = new Array( length );
			progressContexts = new Array( length );
			resolveContexts = new Array( length );
			for ( ; i < length; i++ ) {
				if ( resolveValues[ i ] && jQuery.isFunction( resolveValues[ i ].promise ) ) {
					resolveValues[ i ].promise()
						.done( updateFunc( i, resolveContexts, resolveValues ) )
						.fail( deferred.reject )
						.progress( updateFunc( i, progressContexts, progressValues ) );
				} else {
					--remaining;
				}
			}
		}

		// if we're not waiting on anything, resolve the master
		if ( !remaining ) {
			deferred.resolveWith( resolveContexts, resolveValues );
		}

		return deferred.promise();
	}
});


// The deferred used on DOM ready
var readyList;

jQuery.fn.ready = function( fn ) {
	// Add the callback
	jQuery.ready.promise().done( fn );

	return this;
};

jQuery.extend({
	// Is the DOM ready to be used? Set to true once it occurs.
	isReady: false,

	// A counter to track how many items to wait for before
	// the ready event fires. See #6781
	readyWait: 1,

	// Hold (or release) the ready event
	holdReady: function( hold ) {
		if ( hold ) {
			jQuery.readyWait++;
		} else {
			jQuery.ready( true );
		}
	},

	// Handle when the DOM is ready
	ready: function( wait ) {

		// Abort if there are pending holds or we're already ready
		if ( wait === true ? --jQuery.readyWait : jQuery.isReady ) {
			return;
		}

		// Make sure body exists, at least, in case IE gets a little overzealous (ticket #5443).
		if ( !document.body ) {
			return setTimeout( jQuery.ready );
		}

		// Remember that the DOM is ready
		jQuery.isReady = true;

		// If a normal DOM Ready event fired, decrement, and wait if need be
		if ( wait !== true && --jQuery.readyWait > 0 ) {
			return;
		}

		// If there are functions bound, to execute
		readyList.resolveWith( document, [ jQuery ] );

		// Trigger any bound ready events
		if ( jQuery.fn.triggerHandler ) {
			jQuery( document ).triggerHandler( "ready" );
			jQuery( document ).off( "ready" );
		}
	}
});

/**
 * Clean-up method for dom ready events
 */
function detach() {
	if ( document.addEventListener ) {
		document.removeEventListener( "DOMContentLoaded", completed, false );
		window.removeEventListener( "load", completed, false );

	} else {
		document.detachEvent( "onreadystatechange", completed );
		window.detachEvent( "onload", completed );
	}
}

/**
 * The ready event handler and self cleanup method
 */
function completed() {
	// readyState === "complete" is good enough for us to call the dom ready in oldIE
	if ( document.addEventListener || event.type === "load" || document.readyState === "complete" ) {
		detach();
		jQuery.ready();
	}
}

jQuery.ready.promise = function( obj ) {
	if ( !readyList ) {

		readyList = jQuery.Deferred();

		// Catch cases where $(document).ready() is called after the browser event has already occurred.
		// we once tried to use readyState "interactive" here, but it caused issues like the one
		// discovered by ChrisS here: http://bugs.jquery.com/ticket/12282#comment:15
		if ( document.readyState === "complete" ) {
			// Handle it asynchronously to allow scripts the opportunity to delay ready
			setTimeout( jQuery.ready );

		// Standards-based browsers support DOMContentLoaded
		} else if ( document.addEventListener ) {
			// Use the handy event callback
			document.addEventListener( "DOMContentLoaded", completed, false );

			// A fallback to window.onload, that will always work
			window.addEventListener( "load", completed, false );

		// If IE event model is used
		} else {
			// Ensure firing before onload, maybe late but safe also for iframes
			document.attachEvent( "onreadystatechange", completed );

			// A fallback to window.onload, that will always work
			window.attachEvent( "onload", completed );

			// If IE and not a frame
			// continually check to see if the document is ready
			var top = false;

			try {
				top = window.frameElement == null && document.documentElement;
			} catch(e) {}

			if ( top && top.doScroll ) {
				(function doScrollCheck() {
					if ( !jQuery.isReady ) {

						try {
							// Use the trick by Diego Perini
							// http://javascript.nwbox.com/IEContentLoaded/
							top.doScroll("left");
						} catch(e) {
							return setTimeout( doScrollCheck, 50 );
						}

						// detach all dom ready events
						detach();

						// and execute any waiting functions
						jQuery.ready();
					}
				})();
			}
		}
	}
	return readyList.promise( obj );
};


var strundefined = typeof undefined;



// Support: IE<9
// Iteration over object's inherited properties before its own
var i;
for ( i in jQuery( support ) ) {
	break;
}
support.ownLast = i !== "0";

// Note: most support tests are defined in their respective modules.
// false until the test is run
support.inlineBlockNeedsLayout = false;

// Execute ASAP in case we need to set body.style.zoom
jQuery(function() {
	// Minified: var a,b,c,d
	var val, div, body, container;

	body = document.getElementsByTagName( "body" )[ 0 ];
	if ( !body || !body.style ) {
		// Return for frameset docs that don't have a body
		return;
	}

	// Setup
	div = document.createElement( "div" );
	container = document.createElement( "div" );
	container.style.cssText = "position:absolute;border:0;width:0;height:0;top:0;left:-9999px";
	body.appendChild( container ).appendChild( div );

	if ( typeof div.style.zoom !== strundefined ) {
		// Support: IE<8
		// Check if natively block-level elements act like inline-block
		// elements when setting their display to 'inline' and giving
		// them layout
		div.style.cssText = "display:inline;margin:0;border:0;padding:1px;width:1px;zoom:1";

		support.inlineBlockNeedsLayout = val = div.offsetWidth === 3;
		if ( val ) {
			// Prevent IE 6 from affecting layout for positioned elements #11048
			// Prevent IE from shrinking the body in IE 7 mode #12869
			// Support: IE<8
			body.style.zoom = 1;
		}
	}

	body.removeChild( container );
});




(function() {
	var div = document.createElement( "div" );

	// Execute the test only if not already executed in another module.
	if (support.deleteExpando == null) {
		// Support: IE<9
		support.deleteExpando = true;
		try {
			delete div.test;
		} catch( e ) {
			support.deleteExpando = false;
		}
	}

	// Null elements to avoid leaks in IE.
	div = null;
})();


/**
 * Determines whether an object can have data
 */
jQuery.acceptData = function( elem ) {
	var noData = jQuery.noData[ (elem.nodeName + " ").toLowerCase() ],
		nodeType = +elem.nodeType || 1;

	// Do not set data on non-element DOM nodes because it will not be cleared (#8335).
	return nodeType !== 1 && nodeType !== 9 ?
		false :

		// Nodes accept data unless otherwise specified; rejection can be conditional
		!noData || noData !== true && elem.getAttribute("classid") === noData;
};


var rbrace = /^(?:\{[\w\W]*\}|\[[\w\W]*\])$/,
	rmultiDash = /([A-Z])/g;

function dataAttr( elem, key, data ) {
	// If nothing was found internally, try to fetch any
	// data from the HTML5 data-* attribute
	if ( data === undefined && elem.nodeType === 1 ) {

		var name = "data-" + key.replace( rmultiDash, "-$1" ).toLowerCase();

		data = elem.getAttribute( name );

		if ( typeof data === "string" ) {
			try {
				data = data === "true" ? true :
					data === "false" ? false :
					data === "null" ? null :
					// Only convert to a number if it doesn't change the string
					+data + "" === data ? +data :
					rbrace.test( data ) ? jQuery.parseJSON( data ) :
					data;
			} catch( e ) {}

			// Make sure we set the data so it isn't changed later
			jQuery.data( elem, key, data );

		} else {
			data = undefined;
		}
	}

	return data;
}

// checks a cache object for emptiness
function isEmptyDataObject( obj ) {
	var name;
	for ( name in obj ) {

		// if the public data object is empty, the private is still empty
		if ( name === "data" && jQuery.isEmptyObject( obj[name] ) ) {
			continue;
		}
		if ( name !== "toJSON" ) {
			return false;
		}
	}

	return true;
}

function internalData( elem, name, data, pvt /* Internal Use Only */ ) {
	if ( !jQuery.acceptData( elem ) ) {
		return;
	}

	var ret, thisCache,
		internalKey = jQuery.expando,

		// We have to handle DOM nodes and JS objects differently because IE6-7
		// can't GC object references properly across the DOM-JS boundary
		isNode = elem.nodeType,

		// Only DOM nodes need the global jQuery cache; JS object data is
		// attached directly to the object so GC can occur automatically
		cache = isNode ? jQuery.cache : elem,

		// Only defining an ID for JS objects if its cache already exists allows
		// the code to shortcut on the same path as a DOM node with no cache
		id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;

	// Avoid doing any more work than we need to when trying to get data on an
	// object that has no data at all
	if ( (!id || !cache[id] || (!pvt && !cache[id].data)) && data === undefined && typeof name === "string" ) {
		return;
	}

	if ( !id ) {
		// Only DOM nodes need a new unique ID for each element since their data
		// ends up in the global cache
		if ( isNode ) {
			id = elem[ internalKey ] = deletedIds.pop() || jQuery.guid++;
		} else {
			id = internalKey;
		}
	}

	if ( !cache[ id ] ) {
		// Avoid exposing jQuery metadata on plain JS objects when the object
		// is serialized using JSON.stringify
		cache[ id ] = isNode ? {} : { toJSON: jQuery.noop };
	}

	// An object can be passed to jQuery.data instead of a key/value pair; this gets
	// shallow copied over onto the existing cache
	if ( typeof name === "object" || typeof name === "function" ) {
		if ( pvt ) {
			cache[ id ] = jQuery.extend( cache[ id ], name );
		} else {
			cache[ id ].data = jQuery.extend( cache[ id ].data, name );
		}
	}

	thisCache = cache[ id ];

	// jQuery data() is stored in a separate object inside the object's internal data
	// cache in order to avoid key collisions between internal data and user-defined
	// data.
	if ( !pvt ) {
		if ( !thisCache.data ) {
			thisCache.data = {};
		}

		thisCache = thisCache.data;
	}

	if ( data !== undefined ) {
		thisCache[ jQuery.camelCase( name ) ] = data;
	}

	// Check for both converted-to-camel and non-converted data property names
	// If a data property was specified
	if ( typeof name === "string" ) {

		// First Try to find as-is property data
		ret = thisCache[ name ];

		// Test for null|undefined property data
		if ( ret == null ) {

			// Try to find the camelCased property
			ret = thisCache[ jQuery.camelCase( name ) ];
		}
	} else {
		ret = thisCache;
	}

	return ret;
}

function internalRemoveData( elem, name, pvt ) {
	if ( !jQuery.acceptData( elem ) ) {
		return;
	}

	var thisCache, i,
		isNode = elem.nodeType,

		// See jQuery.data for more information
		cache = isNode ? jQuery.cache : elem,
		id = isNode ? elem[ jQuery.expando ] : jQuery.expando;

	// If there is already no cache entry for this object, there is no
	// purpose in continuing
	if ( !cache[ id ] ) {
		return;
	}

	if ( name ) {

		thisCache = pvt ? cache[ id ] : cache[ id ].data;

		if ( thisCache ) {

			// Support array or space separated string names for data keys
			if ( !jQuery.isArray( name ) ) {

				// try the string as a key before any manipulation
				if ( name in thisCache ) {
					name = [ name ];
				} else {

					// split the camel cased version by spaces unless a key with the spaces exists
					name = jQuery.camelCase( name );
					if ( name in thisCache ) {
						name = [ name ];
					} else {
						name = name.split(" ");
					}
				}
			} else {
				// If "name" is an array of keys...
				// When data is initially created, via ("key", "val") signature,
				// keys will be converted to camelCase.
				// Since there is no way to tell _how_ a key was added, remove
				// both plain key and camelCase key. #12786
				// This will only penalize the array argument path.
				name = name.concat( jQuery.map( name, jQuery.camelCase ) );
			}

			i = name.length;
			while ( i-- ) {
				delete thisCache[ name[i] ];
			}

			// If there is no data left in the cache, we want to continue
			// and let the cache object itself get destroyed
			if ( pvt ? !isEmptyDataObject(thisCache) : !jQuery.isEmptyObject(thisCache) ) {
				return;
			}
		}
	}

	// See jQuery.data for more information
	if ( !pvt ) {
		delete cache[ id ].data;

		// Don't destroy the parent cache unless the internal data object
		// had been the only thing left in it
		if ( !isEmptyDataObject( cache[ id ] ) ) {
			return;
		}
	}

	// Destroy the cache
	if ( isNode ) {
		jQuery.cleanData( [ elem ], true );

	// Use delete when supported for expandos or `cache` is not a window per isWindow (#10080)
	/* jshint eqeqeq: false */
	} else if ( support.deleteExpando || cache != cache.window ) {
		/* jshint eqeqeq: true */
		delete cache[ id ];

	// When all else fails, null
	} else {
		cache[ id ] = null;
	}
}

jQuery.extend({
	cache: {},

	// The following elements (space-suffixed to avoid Object.prototype collisions)
	// throw uncatchable exceptions if you attempt to set expando properties
	noData: {
		"applet ": true,
		"embed ": true,
		// ...but Flash objects (which have this classid) *can* handle expandos
		"object ": "clsid:D27CDB6E-AE6D-11cf-96B8-444553540000"
	},

	hasData: function( elem ) {
		elem = elem.nodeType ? jQuery.cache[ elem[jQuery.expando] ] : elem[ jQuery.expando ];
		return !!elem && !isEmptyDataObject( elem );
	},

	data: function( elem, name, data ) {
		return internalData( elem, name, data );
	},

	removeData: function( elem, name ) {
		return internalRemoveData( elem, name );
	},

	// For internal use only.
	_data: function( elem, name, data ) {
		return internalData( elem, name, data, true );
	},

	_removeData: function( elem, name ) {
		return internalRemoveData( elem, name, true );
	}
});

jQuery.fn.extend({
	data: function( key, value ) {
		var i, name, data,
			elem = this[0],
			attrs = elem && elem.attributes;

		// Special expections of .data basically thwart jQuery.access,
		// so implement the relevant behavior ourselves

		// Gets all values
		if ( key === undefined ) {
			if ( this.length ) {
				data = jQuery.data( elem );

				if ( elem.nodeType === 1 && !jQuery._data( elem, "parsedAttrs" ) ) {
					i = attrs.length;
					while ( i-- ) {

						// Support: IE11+
						// The attrs elements can be null (#14894)
						if ( attrs[ i ] ) {
							name = attrs[ i ].name;
							if ( name.indexOf( "data-" ) === 0 ) {
								name = jQuery.camelCase( name.slice(5) );
								dataAttr( elem, name, data[ name ] );
							}
						}
					}
					jQuery._data( elem, "parsedAttrs", true );
				}
			}

			return data;
		}

		// Sets multiple values
		if ( typeof key === "object" ) {
			return this.each(function() {
				jQuery.data( this, key );
			});
		}

		return arguments.length > 1 ?

			// Sets one value
			this.each(function() {
				jQuery.data( this, key, value );
			}) :

			// Gets one value
			// Try to fetch any internally stored data first
			elem ? dataAttr( elem, key, jQuery.data( elem, key ) ) : undefined;
	},

	removeData: function( key ) {
		return this.each(function() {
			jQuery.removeData( this, key );
		});
	}
});


jQuery.extend({
	queue: function( elem, type, data ) {
		var queue;

		if ( elem ) {
			type = ( type || "fx" ) + "queue";
			queue = jQuery._data( elem, type );

			// Speed up dequeue by getting out quickly if this is just a lookup
			if ( data ) {
				if ( !queue || jQuery.isArray(data) ) {
					queue = jQuery._data( elem, type, jQuery.makeArray(data) );
				} else {
					queue.push( data );
				}
			}
			return queue || [];
		}
	},

	dequeue: function( elem, type ) {
		type = type || "fx";

		var queue = jQuery.queue( elem, type ),
			startLength = queue.length,
			fn = queue.shift(),
			hooks = jQuery._queueHooks( elem, type ),
			next = function() {
				jQuery.dequeue( elem, type );
			};

		// If the fx queue is dequeued, always remove the progress sentinel
		if ( fn === "inprogress" ) {
			fn = queue.shift();
			startLength--;
		}

		if ( fn ) {

			// Add a progress sentinel to prevent the fx queue from being
			// automatically dequeued
			if ( type === "fx" ) {
				queue.unshift( "inprogress" );
			}

			// clear up the last queue stop function
			delete hooks.stop;
			fn.call( elem, next, hooks );
		}

		if ( !startLength && hooks ) {
			hooks.empty.fire();
		}
	},

	// not intended for public consumption - generates a queueHooks object, or returns the current one
	_queueHooks: function( elem, type ) {
		var key = type + "queueHooks";
		return jQuery._data( elem, key ) || jQuery._data( elem, key, {
			empty: jQuery.Callbacks("once memory").add(function() {
				jQuery._removeData( elem, type + "queue" );
				jQuery._removeData( elem, key );
			})
		});
	}
});

jQuery.fn.extend({
	queue: function( type, data ) {
		var setter = 2;

		if ( typeof type !== "string" ) {
			data = type;
			type = "fx";
			setter--;
		}

		if ( arguments.length < setter ) {
			return jQuery.queue( this[0], type );
		}

		return data === undefined ?
			this :
			this.each(function() {
				var queue = jQuery.queue( this, type, data );

				// ensure a hooks for this queue
				jQuery._queueHooks( this, type );

				if ( type === "fx" && queue[0] !== "inprogress" ) {
					jQuery.dequeue( this, type );
				}
			});
	},
	dequeue: function( type ) {
		return this.each(function() {
			jQuery.dequeue( this, type );
		});
	},
	clearQueue: function( type ) {
		return this.queue( type || "fx", [] );
	},
	// Get a promise resolved when queues of a certain type
	// are emptied (fx is the type by default)
	promise: function( type, obj ) {
		var tmp,
			count = 1,
			defer = jQuery.Deferred(),
			elements = this,
			i = this.length,
			resolve = function() {
				if ( !( --count ) ) {
					defer.resolveWith( elements, [ elements ] );
				}
			};

		if ( typeof type !== "string" ) {
			obj = type;
			type = undefined;
		}
		type = type || "fx";

		while ( i-- ) {
			tmp = jQuery._data( elements[ i ], type + "queueHooks" );
			if ( tmp && tmp.empty ) {
				count++;
				tmp.empty.add( resolve );
			}
		}
		resolve();
		return defer.promise( obj );
	}
});
var pnum = (/[+-]?(?:\d*\.|)\d+(?:[eE][+-]?\d+|)/).source;

var cssExpand = [ "Top", "Right", "Bottom", "Left" ];

var isHidden = function( elem, el ) {
		// isHidden might be called from jQuery#filter function;
		// in that case, element will be second argument
		elem = el || elem;
		return jQuery.css( elem, "display" ) === "none" || !jQuery.contains( elem.ownerDocument, elem );
	};



// Multifunctional method to get and set values of a collection
// The value/s can optionally be executed if it's a function
var access = jQuery.access = function( elems, fn, key, value, chainable, emptyGet, raw ) {
	var i = 0,
		length = elems.length,
		bulk = key == null;

	// Sets many values
	if ( jQuery.type( key ) === "object" ) {
		chainable = true;
		for ( i in key ) {
			jQuery.access( elems, fn, i, key[i], true, emptyGet, raw );
		}

	// Sets one value
	} else if ( value !== undefined ) {
		chainable = true;

		if ( !jQuery.isFunction( value ) ) {
			raw = true;
		}

		if ( bulk ) {
			// Bulk operations run against the entire set
			if ( raw ) {
				fn.call( elems, value );
				fn = null;

			// ...except when executing function values
			} else {
				bulk = fn;
				fn = function( elem, key, value ) {
					return bulk.call( jQuery( elem ), value );
				};
			}
		}

		if ( fn ) {
			for ( ; i < length; i++ ) {
				fn( elems[i], key, raw ? value : value.call( elems[i], i, fn( elems[i], key ) ) );
			}
		}
	}

	return chainable ?
		elems :

		// Gets
		bulk ?
			fn.call( elems ) :
			length ? fn( elems[0], key ) : emptyGet;
};
var rcheckableType = (/^(?:checkbox|radio)$/i);



(function() {
	// Minified: var a,b,c
	var input = document.createElement( "input" ),
		div = document.createElement( "div" ),
		fragment = document.createDocumentFragment();

	// Setup
	div.innerHTML = "  <link/><table></table><a href='/a'>a</a><input type='checkbox'/>";

	// IE strips leading whitespace when .innerHTML is used
	support.leadingWhitespace = div.firstChild.nodeType === 3;

	// Make sure that tbody elements aren't automatically inserted
	// IE will insert them into empty tables
	support.tbody = !div.getElementsByTagName( "tbody" ).length;

	// Make sure that link elements get serialized correctly by innerHTML
	// This requires a wrapper element in IE
	support.htmlSerialize = !!div.getElementsByTagName( "link" ).length;

	// Makes sure cloning an html5 element does not cause problems
	// Where outerHTML is undefined, this still works
	support.html5Clone =
		document.createElement( "nav" ).cloneNode( true ).outerHTML !== "<:nav></:nav>";

	// Check if a disconnected checkbox will retain its checked
	// value of true after appended to the DOM (IE6/7)
	input.type = "checkbox";
	input.checked = true;
	fragment.appendChild( input );
	support.appendChecked = input.checked;

	// Make sure textarea (and checkbox) defaultValue is properly cloned
	// Support: IE6-IE11+
	div.innerHTML = "<textarea>x</textarea>";
	support.noCloneChecked = !!div.cloneNode( true ).lastChild.defaultValue;

	// #11217 - WebKit loses check when the name is after the checked attribute
	fragment.appendChild( div );
	div.innerHTML = "<input type='radio' checked='checked' name='t'/>";

	// Support: Safari 5.1, iOS 5.1, Android 4.x, Android 2.3
	// old WebKit doesn't clone checked state correctly in fragments
	support.checkClone = div.cloneNode( true ).cloneNode( true ).lastChild.checked;

	// Support: IE<9
	// Opera does not clone events (and typeof div.attachEvent === undefined).
	// IE9-10 clones events bound via attachEvent, but they don't trigger with .click()
	support.noCloneEvent = true;
	if ( div.attachEvent ) {
		div.attachEvent( "onclick", function() {
			support.noCloneEvent = false;
		});

		div.cloneNode( true ).click();
	}

	// Execute the test only if not already executed in another module.
	if (support.deleteExpando == null) {
		// Support: IE<9
		support.deleteExpando = true;
		try {
			delete div.test;
		} catch( e ) {
			support.deleteExpando = false;
		}
	}
})();


(function() {
	var i, eventName,
		div = document.createElement( "div" );

	// Support: IE<9 (lack submit/change bubble), Firefox 23+ (lack focusin event)
	for ( i in { submit: true, change: true, focusin: true }) {
		eventName = "on" + i;

		if ( !(support[ i + "Bubbles" ] = eventName in window) ) {
			// Beware of CSP restrictions (https://developer.mozilla.org/en/Security/CSP)
			div.setAttribute( eventName, "t" );
			support[ i + "Bubbles" ] = div.attributes[ eventName ].expando === false;
		}
	}

	// Null elements to avoid leaks in IE.
	div = null;
})();


var rformElems = /^(?:input|select|textarea)$/i,
	rkeyEvent = /^key/,
	rmouseEvent = /^(?:mouse|pointer|contextmenu)|click/,
	rfocusMorph = /^(?:focusinfocus|focusoutblur)$/,
	rtypenamespace = /^([^.]*)(?:\.(.+)|)$/;

function returnTrue() {
	return true;
}

function returnFalse() {
	return false;
}

function safeActiveElement() {
	try {
		return document.activeElement;
	} catch ( err ) { }
}

/*
 * Helper functions for managing events -- not part of the public interface.
 * Props to Dean Edwards' addEvent library for many of the ideas.
 */
jQuery.event = {

	global: {},

	add: function( elem, types, handler, data, selector ) {
		var tmp, events, t, handleObjIn,
			special, eventHandle, handleObj,
			handlers, type, namespaces, origType,
			elemData = jQuery._data( elem );

		// Don't attach events to noData or text/comment nodes (but allow plain objects)
		if ( !elemData ) {
			return;
		}

		// Caller can pass in an object of custom data in lieu of the handler
		if ( handler.handler ) {
			handleObjIn = handler;
			handler = handleObjIn.handler;
			selector = handleObjIn.selector;
		}

		// Make sure that the handler has a unique ID, used to find/remove it later
		if ( !handler.guid ) {
			handler.guid = jQuery.guid++;
		}

		// Init the element's event structure and main handler, if this is the first
		if ( !(events = elemData.events) ) {
			events = elemData.events = {};
		}
		if ( !(eventHandle = elemData.handle) ) {
			eventHandle = elemData.handle = function( e ) {
				// Discard the second event of a jQuery.event.trigger() and
				// when an event is called after a page has unloaded
				return typeof jQuery !== strundefined && (!e || jQuery.event.triggered !== e.type) ?
					jQuery.event.dispatch.apply( eventHandle.elem, arguments ) :
					undefined;
			};
			// Add elem as a property of the handle fn to prevent a memory leak with IE non-native events
			eventHandle.elem = elem;
		}

		// Handle multiple events separated by a space
		types = ( types || "" ).match( rnotwhite ) || [ "" ];
		t = types.length;
		while ( t-- ) {
			tmp = rtypenamespace.exec( types[t] ) || [];
			type = origType = tmp[1];
			namespaces = ( tmp[2] || "" ).split( "." ).sort();

			// There *must* be a type, no attaching namespace-only handlers
			if ( !type ) {
				continue;
			}

			// If event changes its type, use the special event handlers for the changed type
			special = jQuery.event.special[ type ] || {};

			// If selector defined, determine special event api type, otherwise given type
			type = ( selector ? special.delegateType : special.bindType ) || type;

			// Update special based on newly reset type
			special = jQuery.event.special[ type ] || {};

			// handleObj is passed to all event handlers
			handleObj = jQuery.extend({
				type: type,
				origType: origType,
				data: data,
				handler: handler,
				guid: handler.guid,
				selector: selector,
				needsContext: selector && jQuery.expr.match.needsContext.test( selector ),
				namespace: namespaces.join(".")
			}, handleObjIn );

			// Init the event handler queue if we're the first
			if ( !(handlers = events[ type ]) ) {
				handlers = events[ type ] = [];
				handlers.delegateCount = 0;

				// Only use addEventListener/attachEvent if the special events handler returns false
				if ( !special.setup || special.setup.call( elem, data, namespaces, eventHandle ) === false ) {
					// Bind the global event handler to the element
					if ( elem.addEventListener ) {
						elem.addEventListener( type, eventHandle, false );

					} else if ( elem.attachEvent ) {
						elem.attachEvent( "on" + type, eventHandle );
					}
				}
			}

			if ( special.add ) {
				special.add.call( elem, handleObj );

				if ( !handleObj.handler.guid ) {
					handleObj.handler.guid = handler.guid;
				}
			}

			// Add to the element's handler list, delegates in front
			if ( selector ) {
				handlers.splice( handlers.delegateCount++, 0, handleObj );
			} else {
				handlers.push( handleObj );
			}

			// Keep track of which events have ever been used, for event optimization
			jQuery.event.global[ type ] = true;
		}

		// Nullify elem to prevent memory leaks in IE
		elem = null;
	},

	// Detach an event or set of events from an element
	remove: function( elem, types, handler, selector, mappedTypes ) {
		var j, handleObj, tmp,
			origCount, t, events,
			special, handlers, type,
			namespaces, origType,
			elemData = jQuery.hasData( elem ) && jQuery._data( elem );

		if ( !elemData || !(events = elemData.events) ) {
			return;
		}

		// Once for each type.namespace in types; type may be omitted
		types = ( types || "" ).match( rnotwhite ) || [ "" ];
		t = types.length;
		while ( t-- ) {
			tmp = rtypenamespace.exec( types[t] ) || [];
			type = origType = tmp[1];
			namespaces = ( tmp[2] || "" ).split( "." ).sort();

			// Unbind all events (on this namespace, if provided) for the element
			if ( !type ) {
				for ( type in events ) {
					jQuery.event.remove( elem, type + types[ t ], handler, selector, true );
				}
				continue;
			}

			special = jQuery.event.special[ type ] || {};
			type = ( selector ? special.delegateType : special.bindType ) || type;
			handlers = events[ type ] || [];
			tmp = tmp[2] && new RegExp( "(^|\\.)" + namespaces.join("\\.(?:.*\\.|)") + "(\\.|$)" );

			// Remove matching events
			origCount = j = handlers.length;
			while ( j-- ) {
				handleObj = handlers[ j ];

				if ( ( mappedTypes || origType === handleObj.origType ) &&
					( !handler || handler.guid === handleObj.guid ) &&
					( !tmp || tmp.test( handleObj.namespace ) ) &&
					( !selector || selector === handleObj.selector || selector === "**" && handleObj.selector ) ) {
					handlers.splice( j, 1 );

					if ( handleObj.selector ) {
						handlers.delegateCount--;
					}
					if ( special.remove ) {
						special.remove.call( elem, handleObj );
					}
				}
			}

			// Remove generic event handler if we removed something and no more handlers exist
			// (avoids potential for endless recursion during removal of special event handlers)
			if ( origCount && !handlers.length ) {
				if ( !special.teardown || special.teardown.call( elem, namespaces, elemData.handle ) === false ) {
					jQuery.removeEvent( elem, type, elemData.handle );
				}

				delete events[ type ];
			}
		}

		// Remove the expando if it's no longer used
		if ( jQuery.isEmptyObject( events ) ) {
			delete elemData.handle;

			// removeData also checks for emptiness and clears the expando if empty
			// so use it instead of delete
			jQuery._removeData( elem, "events" );
		}
	},

	trigger: function( event, data, elem, onlyHandlers ) {
		var handle, ontype, cur,
			bubbleType, special, tmp, i,
			eventPath = [ elem || document ],
			type = hasOwn.call( event, "type" ) ? event.type : event,
			namespaces = hasOwn.call( event, "namespace" ) ? event.namespace.split(".") : [];

		cur = tmp = elem = elem || document;

		// Don't do events on text and comment nodes
		if ( elem.nodeType === 3 || elem.nodeType === 8 ) {
			return;
		}

		// focus/blur morphs to focusin/out; ensure we're not firing them right now
		if ( rfocusMorph.test( type + jQuery.event.triggered ) ) {
			return;
		}

		if ( type.indexOf(".") >= 0 ) {
			// Namespaced trigger; create a regexp to match event type in handle()
			namespaces = type.split(".");
			type = namespaces.shift();
			namespaces.sort();
		}
		ontype = type.indexOf(":") < 0 && "on" + type;

		// Caller can pass in a jQuery.Event object, Object, or just an event type string
		event = event[ jQuery.expando ] ?
			event :
			new jQuery.Event( type, typeof event === "object" && event );

		// Trigger bitmask: & 1 for native handlers; & 2 for jQuery (always true)
		event.isTrigger = onlyHandlers ? 2 : 3;
		event.namespace = namespaces.join(".");
		event.namespace_re = event.namespace ?
			new RegExp( "(^|\\.)" + namespaces.join("\\.(?:.*\\.|)") + "(\\.|$)" ) :
			null;

		// Clean up the event in case it is being reused
		event.result = undefined;
		if ( !event.target ) {
			event.target = elem;
		}

		// Clone any incoming data and prepend the event, creating the handler arg list
		data = data == null ?
			[ event ] :
			jQuery.makeArray( data, [ event ] );

		// Allow special events to draw outside the lines
		special = jQuery.event.special[ type ] || {};
		if ( !onlyHandlers && special.trigger && special.trigger.apply( elem, data ) === false ) {
			return;
		}

		// Determine event propagation path in advance, per W3C events spec (#9951)
		// Bubble up to document, then to window; watch for a global ownerDocument var (#9724)
		if ( !onlyHandlers && !special.noBubble && !jQuery.isWindow( elem ) ) {

			bubbleType = special.delegateType || type;
			if ( !rfocusMorph.test( bubbleType + type ) ) {
				cur = cur.parentNode;
			}
			for ( ; cur; cur = cur.parentNode ) {
				eventPath.push( cur );
				tmp = cur;
			}

			// Only add window if we got to document (e.g., not plain obj or detached DOM)
			if ( tmp === (elem.ownerDocument || document) ) {
				eventPath.push( tmp.defaultView || tmp.parentWindow || window );
			}
		}

		// Fire handlers on the event path
		i = 0;
		while ( (cur = eventPath[i++]) && !event.isPropagationStopped() ) {

			event.type = i > 1 ?
				bubbleType :
				special.bindType || type;

			// jQuery handler
			handle = ( jQuery._data( cur, "events" ) || {} )[ event.type ] && jQuery._data( cur, "handle" );
			if ( handle ) {
				handle.apply( cur, data );
			}

			// Native handler
			handle = ontype && cur[ ontype ];
			if ( handle && handle.apply && jQuery.acceptData( cur ) ) {
				event.result = handle.apply( cur, data );
				if ( event.result === false ) {
					event.preventDefault();
				}
			}
		}
		event.type = type;

		// If nobody prevented the default action, do it now
		if ( !onlyHandlers && !event.isDefaultPrevented() ) {

			if ( (!special._default || special._default.apply( eventPath.pop(), data ) === false) &&
				jQuery.acceptData( elem ) ) {

				// Call a native DOM method on the target with the same name name as the event.
				// Can't use an .isFunction() check here because IE6/7 fails that test.
				// Don't do default actions on window, that's where global variables be (#6170)
				if ( ontype && elem[ type ] && !jQuery.isWindow( elem ) ) {

					// Don't re-trigger an onFOO event when we call its FOO() method
					tmp = elem[ ontype ];

					if ( tmp ) {
						elem[ ontype ] = null;
					}

					// Prevent re-triggering of the same event, since we already bubbled it above
					jQuery.event.triggered = type;
					try {
						elem[ type ]();
					} catch ( e ) {
						// IE<9 dies on focus/blur to hidden element (#1486,#12518)
						// only reproducible on winXP IE8 native, not IE9 in IE8 mode
					}
					jQuery.event.triggered = undefined;

					if ( tmp ) {
						elem[ ontype ] = tmp;
					}
				}
			}
		}

		return event.result;
	},

	dispatch: function( event ) {

		// Make a writable jQuery.Event from the native event object
		event = jQuery.event.fix( event );

		var i, ret, handleObj, matched, j,
			handlerQueue = [],
			args = slice.call( arguments ),
			handlers = ( jQuery._data( this, "events" ) || {} )[ event.type ] || [],
			special = jQuery.event.special[ event.type ] || {};

		// Use the fix-ed jQuery.Event rather than the (read-only) native event
		args[0] = event;
		event.delegateTarget = this;

		// Call the preDispatch hook for the mapped type, and let it bail if desired
		if ( special.preDispatch && special.preDispatch.call( this, event ) === false ) {
			return;
		}

		// Determine handlers
		handlerQueue = jQuery.event.handlers.call( this, event, handlers );

		// Run delegates first; they may want to stop propagation beneath us
		i = 0;
		while ( (matched = handlerQueue[ i++ ]) && !event.isPropagationStopped() ) {
			event.currentTarget = matched.elem;

			j = 0;
			while ( (handleObj = matched.handlers[ j++ ]) && !event.isImmediatePropagationStopped() ) {

				// Triggered event must either 1) have no namespace, or
				// 2) have namespace(s) a subset or equal to those in the bound event (both can have no namespace).
				if ( !event.namespace_re || event.namespace_re.test( handleObj.namespace ) ) {

					event.handleObj = handleObj;
					event.data = handleObj.data;

					ret = ( (jQuery.event.special[ handleObj.origType ] || {}).handle || handleObj.handler )
							.apply( matched.elem, args );

					if ( ret !== undefined ) {
						if ( (event.result = ret) === false ) {
							event.preventDefault();
							event.stopPropagation();
						}
					}
				}
			}
		}

		// Call the postDispatch hook for the mapped type
		if ( special.postDispatch ) {
			special.postDispatch.call( this, event );
		}

		return event.result;
	},

	handlers: function( event, handlers ) {
		var sel, handleObj, matches, i,
			handlerQueue = [],
			delegateCount = handlers.delegateCount,
			cur = event.target;

		// Find delegate handlers
		// Black-hole SVG <use> instance trees (#13180)
		// Avoid non-left-click bubbling in Firefox (#3861)
		if ( delegateCount && cur.nodeType && (!event.button || event.type !== "click") ) {

			/* jshint eqeqeq: false */
			for ( ; cur != this; cur = cur.parentNode || this ) {
				/* jshint eqeqeq: true */

				// Don't check non-elements (#13208)
				// Don't process clicks on disabled elements (#6911, #8165, #11382, #11764)
				if ( cur.nodeType === 1 && (cur.disabled !== true || event.type !== "click") ) {
					matches = [];
					for ( i = 0; i < delegateCount; i++ ) {
						handleObj = handlers[ i ];

						// Don't conflict with Object.prototype properties (#13203)
						sel = handleObj.selector + " ";

						if ( matches[ sel ] === undefined ) {
							matches[ sel ] = handleObj.needsContext ?
								jQuery( sel, this ).index( cur ) >= 0 :
								jQuery.find( sel, this, null, [ cur ] ).length;
						}
						if ( matches[ sel ] ) {
							matches.push( handleObj );
						}
					}
					if ( matches.length ) {
						handlerQueue.push({ elem: cur, handlers: matches });
					}
				}
			}
		}

		// Add the remaining (directly-bound) handlers
		if ( delegateCount < handlers.length ) {
			handlerQueue.push({ elem: this, handlers: handlers.slice( delegateCount ) });
		}

		return handlerQueue;
	},

	fix: function( event ) {
		if ( event[ jQuery.expando ] ) {
			return event;
		}

		// Create a writable copy of the event object and normalize some properties
		var i, prop, copy,
			type = event.type,
			originalEvent = event,
			fixHook = this.fixHooks[ type ];

		if ( !fixHook ) {
			this.fixHooks[ type ] = fixHook =
				rmouseEvent.test( type ) ? this.mouseHooks :
				rkeyEvent.test( type ) ? this.keyHooks :
				{};
		}
		copy = fixHook.props ? this.props.concat( fixHook.props ) : this.props;

		event = new jQuery.Event( originalEvent );

		i = copy.length;
		while ( i-- ) {
			prop = copy[ i ];
			event[ prop ] = originalEvent[ prop ];
		}

		// Support: IE<9
		// Fix target property (#1925)
		if ( !event.target ) {
			event.target = originalEvent.srcElement || document;
		}

		// Support: Chrome 23+, Safari?
		// Target should not be a text node (#504, #13143)
		if ( event.target.nodeType === 3 ) {
			event.target = event.target.parentNode;
		}

		// Support: IE<9
		// For mouse/key events, metaKey==false if it's undefined (#3368, #11328)
		event.metaKey = !!event.metaKey;

		return fixHook.filter ? fixHook.filter( event, originalEvent ) : event;
	},

	// Includes some event props shared by KeyEvent and MouseEvent
	props: "altKey bubbles cancelable ctrlKey currentTarget eventPhase metaKey relatedTarget shiftKey target timeStamp view which".split(" "),

	fixHooks: {},

	keyHooks: {
		props: "char charCode key keyCode".split(" "),
		filter: function( event, original ) {

			// Add which for key events
			if ( event.which == null ) {
				event.which = original.charCode != null ? original.charCode : original.keyCode;
			}

			return event;
		}
	},

	mouseHooks: {
		props: "button buttons clientX clientY fromElement offsetX offsetY pageX pageY screenX screenY toElement".split(" "),
		filter: function( event, original ) {
			var body, eventDoc, doc,
				button = original.button,
				fromElement = original.fromElement;

			// Calculate pageX/Y if missing and clientX/Y available
			if ( event.pageX == null && original.clientX != null ) {
				eventDoc = event.target.ownerDocument || document;
				doc = eventDoc.documentElement;
				body = eventDoc.body;

				event.pageX = original.clientX + ( doc && doc.scrollLeft || body && body.scrollLeft || 0 ) - ( doc && doc.clientLeft || body && body.clientLeft || 0 );
				event.pageY = original.clientY + ( doc && doc.scrollTop  || body && body.scrollTop  || 0 ) - ( doc && doc.clientTop  || body && body.clientTop  || 0 );
			}

			// Add relatedTarget, if necessary
			if ( !event.relatedTarget && fromElement ) {
				event.relatedTarget = fromElement === event.target ? original.toElement : fromElement;
			}

			// Add which for click: 1 === left; 2 === middle; 3 === right
			// Note: button is not normalized, so don't use it
			if ( !event.which && button !== undefined ) {
				event.which = ( button & 1 ? 1 : ( button & 2 ? 3 : ( button & 4 ? 2 : 0 ) ) );
			}

			return event;
		}
	},

	special: {
		load: {
			// Prevent triggered image.load events from bubbling to window.load
			noBubble: true
		},
		focus: {
			// Fire native event if possible so blur/focus sequence is correct
			trigger: function() {
				if ( this !== safeActiveElement() && this.focus ) {
					try {
						this.focus();
						return false;
					} catch ( e ) {
						// Support: IE<9
						// If we error on focus to hidden element (#1486, #12518),
						// let .trigger() run the handlers
					}
				}
			},
			delegateType: "focusin"
		},
		blur: {
			trigger: function() {
				if ( this === safeActiveElement() && this.blur ) {
					this.blur();
					return false;
				}
			},
			delegateType: "focusout"
		},
		click: {
			// For checkbox, fire native event so checked state will be right
			trigger: function() {
				if ( jQuery.nodeName( this, "input" ) && this.type === "checkbox" && this.click ) {
					this.click();
					return false;
				}
			},

			// For cross-browser consistency, don't fire native .click() on links
			_default: function( event ) {
				return jQuery.nodeName( event.target, "a" );
			}
		},

		beforeunload: {
			postDispatch: function( event ) {

				// Support: Firefox 20+
				// Firefox doesn't alert if the returnValue field is not set.
				if ( event.result !== undefined && event.originalEvent ) {
					event.originalEvent.returnValue = event.result;
				}
			}
		}
	},

	simulate: function( type, elem, event, bubble ) {
		// Piggyback on a donor event to simulate a different one.
		// Fake originalEvent to avoid donor's stopPropagation, but if the
		// simulated event prevents default then we do the same on the donor.
		var e = jQuery.extend(
			new jQuery.Event(),
			event,
			{
				type: type,
				isSimulated: true,
				originalEvent: {}
			}
		);
		if ( bubble ) {
			jQuery.event.trigger( e, null, elem );
		} else {
			jQuery.event.dispatch.call( elem, e );
		}
		if ( e.isDefaultPrevented() ) {
			event.preventDefault();
		}
	}
};

jQuery.removeEvent = document.removeEventListener ?
	function( elem, type, handle ) {
		if ( elem.removeEventListener ) {
			elem.removeEventListener( type, handle, false );
		}
	} :
	function( elem, type, handle ) {
		var name = "on" + type;

		if ( elem.detachEvent ) {

			// #8545, #7054, preventing memory leaks for custom events in IE6-8
			// detachEvent needed property on element, by name of that event, to properly expose it to GC
			if ( typeof elem[ name ] === strundefined ) {
				elem[ name ] = null;
			}

			elem.detachEvent( name, handle );
		}
	};

jQuery.Event = function( src, props ) {
	// Allow instantiation without the 'new' keyword
	if ( !(this instanceof jQuery.Event) ) {
		return new jQuery.Event( src, props );
	}

	// Event object
	if ( src && src.type ) {
		this.originalEvent = src;
		this.type = src.type;

		// Events bubbling up the document may have been marked as prevented
		// by a handler lower down the tree; reflect the correct value.
		this.isDefaultPrevented = src.defaultPrevented ||
				src.defaultPrevented === undefined &&
				// Support: IE < 9, Android < 4.0
				src.returnValue === false ?
			returnTrue :
			returnFalse;

	// Event type
	} else {
		this.type = src;
	}

	// Put explicitly provided properties onto the event object
	if ( props ) {
		jQuery.extend( this, props );
	}

	// Create a timestamp if incoming event doesn't have one
	this.timeStamp = src && src.timeStamp || jQuery.now();

	// Mark it as fixed
	this[ jQuery.expando ] = true;
};

// jQuery.Event is based on DOM3 Events as specified by the ECMAScript Language Binding
// http://www.w3.org/TR/2003/WD-DOM-Level-3-Events-20030331/ecma-script-binding.html
jQuery.Event.prototype = {
	isDefaultPrevented: returnFalse,
	isPropagationStopped: returnFalse,
	isImmediatePropagationStopped: returnFalse,

	preventDefault: function() {
		var e = this.originalEvent;

		this.isDefaultPrevented = returnTrue;
		if ( !e ) {
			return;
		}

		// If preventDefault exists, run it on the original event
		if ( e.preventDefault ) {
			e.preventDefault();

		// Support: IE
		// Otherwise set the returnValue property of the original event to false
		} else {
			e.returnValue = false;
		}
	},
	stopPropagation: function() {
		var e = this.originalEvent;

		this.isPropagationStopped = returnTrue;
		if ( !e ) {
			return;
		}
		// If stopPropagation exists, run it on the original event
		if ( e.stopPropagation ) {
			e.stopPropagation();
		}

		// Support: IE
		// Set the cancelBubble property of the original event to true
		e.cancelBubble = true;
	},
	stopImmediatePropagation: function() {
		var e = this.originalEvent;

		this.isImmediatePropagationStopped = returnTrue;

		if ( e && e.stopImmediatePropagation ) {
			e.stopImmediatePropagation();
		}

		this.stopPropagation();
	}
};

// Create mouseenter/leave events using mouseover/out and event-time checks
jQuery.each({
	mouseenter: "mouseover",
	mouseleave: "mouseout",
	pointerenter: "pointerover",
	pointerleave: "pointerout"
}, function( orig, fix ) {
	jQuery.event.special[ orig ] = {
		delegateType: fix,
		bindType: fix,

		handle: function( event ) {
			var ret,
				target = this,
				related = event.relatedTarget,
				handleObj = event.handleObj;

			// For mousenter/leave call the handler if related is outside the target.
			// NB: No relatedTarget if the mouse left/entered the browser window
			if ( !related || (related !== target && !jQuery.contains( target, related )) ) {
				event.type = handleObj.origType;
				ret = handleObj.handler.apply( this, arguments );
				event.type = fix;
			}
			return ret;
		}
	};
});

// IE submit delegation
if ( !support.submitBubbles ) {

	jQuery.event.special.submit = {
		setup: function() {
			// Only need this for delegated form submit events
			if ( jQuery.nodeName( this, "form" ) ) {
				return false;
			}

			// Lazy-add a submit handler when a descendant form may potentially be submitted
			jQuery.event.add( this, "click._submit keypress._submit", function( e ) {
				// Node name check avoids a VML-related crash in IE (#9807)
				var elem = e.target,
					form = jQuery.nodeName( elem, "input" ) || jQuery.nodeName( elem, "button" ) ? elem.form : undefined;
				if ( form && !jQuery._data( form, "submitBubbles" ) ) {
					jQuery.event.add( form, "submit._submit", function( event ) {
						event._submit_bubble = true;
					});
					jQuery._data( form, "submitBubbles", true );
				}
			});
			// return undefined since we don't need an event listener
		},

		postDispatch: function( event ) {
			// If form was submitted by the user, bubble the event up the tree
			if ( event._submit_bubble ) {
				delete event._submit_bubble;
				if ( this.parentNode && !event.isTrigger ) {
					jQuery.event.simulate( "submit", this.parentNode, event, true );
				}
			}
		},

		teardown: function() {
			// Only need this for delegated form submit events
			if ( jQuery.nodeName( this, "form" ) ) {
				return false;
			}

			// Remove delegated handlers; cleanData eventually reaps submit handlers attached above
			jQuery.event.remove( this, "._submit" );
		}
	};
}

// IE change delegation and checkbox/radio fix
if ( !support.changeBubbles ) {

	jQuery.event.special.change = {

		setup: function() {

			if ( rformElems.test( this.nodeName ) ) {
				// IE doesn't fire change on a check/radio until blur; trigger it on click
				// after a propertychange. Eat the blur-change in special.change.handle.
				// This still fires onchange a second time for check/radio after blur.
				if ( this.type === "checkbox" || this.type === "radio" ) {
					jQuery.event.add( this, "propertychange._change", function( event ) {
						if ( event.originalEvent.propertyName === "checked" ) {
							this._just_changed = true;
						}
					});
					jQuery.event.add( this, "click._change", function( event ) {
						if ( this._just_changed && !event.isTrigger ) {
							this._just_changed = false;
						}
						// Allow triggered, simulated change events (#11500)
						jQuery.event.simulate( "change", this, event, true );
					});
				}
				return false;
			}
			// Delegated event; lazy-add a change handler on descendant inputs
			jQuery.event.add( this, "beforeactivate._change", function( e ) {
				var elem = e.target;

				if ( rformElems.test( elem.nodeName ) && !jQuery._data( elem, "changeBubbles" ) ) {
					jQuery.event.add( elem, "change._change", function( event ) {
						if ( this.parentNode && !event.isSimulated && !event.isTrigger ) {
							jQuery.event.simulate( "change", this.parentNode, event, true );
						}
					});
					jQuery._data( elem, "changeBubbles", true );
				}
			});
		},

		handle: function( event ) {
			var elem = event.target;

			// Swallow native change events from checkbox/radio, we already triggered them above
			if ( this !== elem || event.isSimulated || event.isTrigger || (elem.type !== "radio" && elem.type !== "checkbox") ) {
				return event.handleObj.handler.apply( this, arguments );
			}
		},

		teardown: function() {
			jQuery.event.remove( this, "._change" );

			return !rformElems.test( this.nodeName );
		}
	};
}

// Create "bubbling" focus and blur events
if ( !support.focusinBubbles ) {
	jQuery.each({ focus: "focusin", blur: "focusout" }, function( orig, fix ) {

		// Attach a single capturing handler on the document while someone wants focusin/focusout
		var handler = function( event ) {
				jQuery.event.simulate( fix, event.target, jQuery.event.fix( event ), true );
			};

		jQuery.event.special[ fix ] = {
			setup: function() {
				var doc = this.ownerDocument || this,
					attaches = jQuery._data( doc, fix );

				if ( !attaches ) {
					doc.addEventListener( orig, handler, true );
				}
				jQuery._data( doc, fix, ( attaches || 0 ) + 1 );
			},
			teardown: function() {
				var doc = this.ownerDocument || this,
					attaches = jQuery._data( doc, fix ) - 1;

				if ( !attaches ) {
					doc.removeEventListener( orig, handler, true );
					jQuery._removeData( doc, fix );
				} else {
					jQuery._data( doc, fix, attaches );
				}
			}
		};
	});
}

jQuery.fn.extend({

	on: function( types, selector, data, fn, /*INTERNAL*/ one ) {
		var type, origFn;

		// Types can be a map of types/handlers
		if ( typeof types === "object" ) {
			// ( types-Object, selector, data )
			if ( typeof selector !== "string" ) {
				// ( types-Object, data )
				data = data || selector;
				selector = undefined;
			}
			for ( type in types ) {
				this.on( type, selector, data, types[ type ], one );
			}
			return this;
		}

		if ( data == null && fn == null ) {
			// ( types, fn )
			fn = selector;
			data = selector = undefined;
		} else if ( fn == null ) {
			if ( typeof selector === "string" ) {
				// ( types, selector, fn )
				fn = data;
				data = undefined;
			} else {
				// ( types, data, fn )
				fn = data;
				data = selector;
				selector = undefined;
			}
		}
		if ( fn === false ) {
			fn = returnFalse;
		} else if ( !fn ) {
			return this;
		}

		if ( one === 1 ) {
			origFn = fn;
			fn = function( event ) {
				// Can use an empty set, since event contains the info
				jQuery().off( event );
				return origFn.apply( this, arguments );
			};
			// Use same guid so caller can remove using origFn
			fn.guid = origFn.guid || ( origFn.guid = jQuery.guid++ );
		}
		return this.each( function() {
			jQuery.event.add( this, types, fn, data, selector );
		});
	},
	one: function( types, selector, data, fn ) {
		return this.on( types, selector, data, fn, 1 );
	},
	off: function( types, selector, fn ) {
		var handleObj, type;
		if ( types && types.preventDefault && types.handleObj ) {
			// ( event )  dispatched jQuery.Event
			handleObj = types.handleObj;
			jQuery( types.delegateTarget ).off(
				handleObj.namespace ? handleObj.origType + "." + handleObj.namespace : handleObj.origType,
				handleObj.selector,
				handleObj.handler
			);
			return this;
		}
		if ( typeof types === "object" ) {
			// ( types-object [, selector] )
			for ( type in types ) {
				this.off( type, selector, types[ type ] );
			}
			return this;
		}
		if ( selector === false || typeof selector === "function" ) {
			// ( types [, fn] )
			fn = selector;
			selector = undefined;
		}
		if ( fn === false ) {
			fn = returnFalse;
		}
		return this.each(function() {
			jQuery.event.remove( this, types, fn, selector );
		});
	},

	trigger: function( type, data ) {
		return this.each(function() {
			jQuery.event.trigger( type, data, this );
		});
	},
	triggerHandler: function( type, data ) {
		var elem = this[0];
		if ( elem ) {
			return jQuery.event.trigger( type, data, elem, true );
		}
	}
});


function createSafeFragment( document ) {
	var list = nodeNames.split( "|" ),
		safeFrag = document.createDocumentFragment();

	if ( safeFrag.createElement ) {
		while ( list.length ) {
			safeFrag.createElement(
				list.pop()
			);
		}
	}
	return safeFrag;
}

var nodeNames = "abbr|article|aside|audio|bdi|canvas|data|datalist|details|figcaption|figure|footer|" +
		"header|hgroup|mark|meter|nav|output|progress|section|summary|time|video",
	rinlinejQuery = / jQuery\d+="(?:null|\d+)"/g,
	rnoshimcache = new RegExp("<(?:" + nodeNames + ")[\\s/>]", "i"),
	rleadingWhitespace = /^\s+/,
	rxhtmlTag = /<(?!area|br|col|embed|hr|img|input|link|meta|param)(([\w:]+)[^>]*)\/>/gi,
	rtagName = /<([\w:]+)/,
	rtbody = /<tbody/i,
	rhtml = /<|&#?\w+;/,
	rnoInnerhtml = /<(?:script|style|link)/i,
	// checked="checked" or checked
	rchecked = /checked\s*(?:[^=]|=\s*.checked.)/i,
	rscriptType = /^$|\/(?:java|ecma)script/i,
	rscriptTypeMasked = /^true\/(.*)/,
	rcleanScript = /^\s*<!(?:\[CDATA\[|--)|(?:\]\]|--)>\s*$/g,

	// We have to close these tags to support XHTML (#13200)
	wrapMap = {
		option: [ 1, "<select multiple='multiple'>", "</select>" ],
		legend: [ 1, "<fieldset>", "</fieldset>" ],
		area: [ 1, "<map>", "</map>" ],
		param: [ 1, "<object>", "</object>" ],
		thead: [ 1, "<table>", "</table>" ],
		tr: [ 2, "<table><tbody>", "</tbody></table>" ],
		col: [ 2, "<table><tbody></tbody><colgroup>", "</colgroup></table>" ],
		td: [ 3, "<table><tbody><tr>", "</tr></tbody></table>" ],

		// IE6-8 can't serialize link, script, style, or any html5 (NoScope) tags,
		// unless wrapped in a div with non-breaking characters in front of it.
		_default: support.htmlSerialize ? [ 0, "", "" ] : [ 1, "X<div>", "</div>"  ]
	},
	safeFragment = createSafeFragment( document ),
	fragmentDiv = safeFragment.appendChild( document.createElement("div") );

wrapMap.optgroup = wrapMap.option;
wrapMap.tbody = wrapMap.tfoot = wrapMap.colgroup = wrapMap.caption = wrapMap.thead;
wrapMap.th = wrapMap.td;

function getAll( context, tag ) {
	var elems, elem,
		i = 0,
		found = typeof context.getElementsByTagName !== strundefined ? context.getElementsByTagName( tag || "*" ) :
			typeof context.querySelectorAll !== strundefined ? context.querySelectorAll( tag || "*" ) :
			undefined;

	if ( !found ) {
		for ( found = [], elems = context.childNodes || context; (elem = elems[i]) != null; i++ ) {
			if ( !tag || jQuery.nodeName( elem, tag ) ) {
				found.push( elem );
			} else {
				jQuery.merge( found, getAll( elem, tag ) );
			}
		}
	}

	return tag === undefined || tag && jQuery.nodeName( context, tag ) ?
		jQuery.merge( [ context ], found ) :
		found;
}

// Used in buildFragment, fixes the defaultChecked property
function fixDefaultChecked( elem ) {
	if ( rcheckableType.test( elem.type ) ) {
		elem.defaultChecked = elem.checked;
	}
}

// Support: IE<8
// Manipulating tables requires a tbody
function manipulationTarget( elem, content ) {
	return jQuery.nodeName( elem, "table" ) &&
		jQuery.nodeName( content.nodeType !== 11 ? content : content.firstChild, "tr" ) ?

		elem.getElementsByTagName("tbody")[0] ||
			elem.appendChild( elem.ownerDocument.createElement("tbody") ) :
		elem;
}

// Replace/restore the type attribute of script elements for safe DOM manipulation
function disableScript( elem ) {
	elem.type = (jQuery.find.attr( elem, "type" ) !== null) + "/" + elem.type;
	return elem;
}
function restoreScript( elem ) {
	var match = rscriptTypeMasked.exec( elem.type );
	if ( match ) {
		elem.type = match[1];
	} else {
		elem.removeAttribute("type");
	}
	return elem;
}

// Mark scripts as having already been evaluated
function setGlobalEval( elems, refElements ) {
	var elem,
		i = 0;
	for ( ; (elem = elems[i]) != null; i++ ) {
		jQuery._data( elem, "globalEval", !refElements || jQuery._data( refElements[i], "globalEval" ) );
	}
}

function cloneCopyEvent( src, dest ) {

	if ( dest.nodeType !== 1 || !jQuery.hasData( src ) ) {
		return;
	}

	var type, i, l,
		oldData = jQuery._data( src ),
		curData = jQuery._data( dest, oldData ),
		events = oldData.events;

	if ( events ) {
		delete curData.handle;
		curData.events = {};

		for ( type in events ) {
			for ( i = 0, l = events[ type ].length; i < l; i++ ) {
				jQuery.event.add( dest, type, events[ type ][ i ] );
			}
		}
	}

	// make the cloned public data object a copy from the original
	if ( curData.data ) {
		curData.data = jQuery.extend( {}, curData.data );
	}
}

function fixCloneNodeIssues( src, dest ) {
	var nodeName, e, data;

	// We do not need to do anything for non-Elements
	if ( dest.nodeType !== 1 ) {
		return;
	}

	nodeName = dest.nodeName.toLowerCase();

	// IE6-8 copies events bound via attachEvent when using cloneNode.
	if ( !support.noCloneEvent && dest[ jQuery.expando ] ) {
		data = jQuery._data( dest );

		for ( e in data.events ) {
			jQuery.removeEvent( dest, e, data.handle );
		}

		// Event data gets referenced instead of copied if the expando gets copied too
		dest.removeAttribute( jQuery.expando );
	}

	// IE blanks contents when cloning scripts, and tries to evaluate newly-set text
	if ( nodeName === "script" && dest.text !== src.text ) {
		disableScript( dest ).text = src.text;
		restoreScript( dest );

	// IE6-10 improperly clones children of object elements using classid.
	// IE10 throws NoModificationAllowedError if parent is null, #12132.
	} else if ( nodeName === "object" ) {
		if ( dest.parentNode ) {
			dest.outerHTML = src.outerHTML;
		}

		// This path appears unavoidable for IE9. When cloning an object
		// element in IE9, the outerHTML strategy above is not sufficient.
		// If the src has innerHTML and the destination does not,
		// copy the src.innerHTML into the dest.innerHTML. #10324
		if ( support.html5Clone && ( src.innerHTML && !jQuery.trim(dest.innerHTML) ) ) {
			dest.innerHTML = src.innerHTML;
		}

	} else if ( nodeName === "input" && rcheckableType.test( src.type ) ) {
		// IE6-8 fails to persist the checked state of a cloned checkbox
		// or radio button. Worse, IE6-7 fail to give the cloned element
		// a checked appearance if the defaultChecked value isn't also set

		dest.defaultChecked = dest.checked = src.checked;

		// IE6-7 get confused and end up setting the value of a cloned
		// checkbox/radio button to an empty string instead of "on"
		if ( dest.value !== src.value ) {
			dest.value = src.value;
		}

	// IE6-8 fails to return the selected option to the default selected
	// state when cloning options
	} else if ( nodeName === "option" ) {
		dest.defaultSelected = dest.selected = src.defaultSelected;

	// IE6-8 fails to set the defaultValue to the correct value when
	// cloning other types of input fields
	} else if ( nodeName === "input" || nodeName === "textarea" ) {
		dest.defaultValue = src.defaultValue;
	}
}

jQuery.extend({
	clone: function( elem, dataAndEvents, deepDataAndEvents ) {
		var destElements, node, clone, i, srcElements,
			inPage = jQuery.contains( elem.ownerDocument, elem );

		if ( support.html5Clone || jQuery.isXMLDoc(elem) || !rnoshimcache.test( "<" + elem.nodeName + ">" ) ) {
			clone = elem.cloneNode( true );

		// IE<=8 does not properly clone detached, unknown element nodes
		} else {
			fragmentDiv.innerHTML = elem.outerHTML;
			fragmentDiv.removeChild( clone = fragmentDiv.firstChild );
		}

		if ( (!support.noCloneEvent || !support.noCloneChecked) &&
				(elem.nodeType === 1 || elem.nodeType === 11) && !jQuery.isXMLDoc(elem) ) {

			// We eschew Sizzle here for performance reasons: http://jsperf.com/getall-vs-sizzle/2
			destElements = getAll( clone );
			srcElements = getAll( elem );

			// Fix all IE cloning issues
			for ( i = 0; (node = srcElements[i]) != null; ++i ) {
				// Ensure that the destination node is not null; Fixes #9587
				if ( destElements[i] ) {
					fixCloneNodeIssues( node, destElements[i] );
				}
			}
		}

		// Copy the events from the original to the clone
		if ( dataAndEvents ) {
			if ( deepDataAndEvents ) {
				srcElements = srcElements || getAll( elem );
				destElements = destElements || getAll( clone );

				for ( i = 0; (node = srcElements[i]) != null; i++ ) {
					cloneCopyEvent( node, destElements[i] );
				}
			} else {
				cloneCopyEvent( elem, clone );
			}
		}

		// Preserve script evaluation history
		destElements = getAll( clone, "script" );
		if ( destElements.length > 0 ) {
			setGlobalEval( destElements, !inPage && getAll( elem, "script" ) );
		}

		destElements = srcElements = node = null;

		// Return the cloned set
		return clone;
	},

	buildFragment: function( elems, context, scripts, selection ) {
		var j, elem, contains,
			tmp, tag, tbody, wrap,
			l = elems.length,

			// Ensure a safe fragment
			safe = createSafeFragment( context ),

			nodes = [],
			i = 0;

		for ( ; i < l; i++ ) {
			elem = elems[ i ];

			if ( elem || elem === 0 ) {

				// Add nodes directly
				if ( jQuery.type( elem ) === "object" ) {
					jQuery.merge( nodes, elem.nodeType ? [ elem ] : elem );

				// Convert non-html into a text node
				} else if ( !rhtml.test( elem ) ) {
					nodes.push( context.createTextNode( elem ) );

				// Convert html into DOM nodes
				} else {
					tmp = tmp || safe.appendChild( context.createElement("div") );

					// Deserialize a standard representation
					tag = (rtagName.exec( elem ) || [ "", "" ])[ 1 ].toLowerCase();
					wrap = wrapMap[ tag ] || wrapMap._default;

					tmp.innerHTML = wrap[1] + elem.replace( rxhtmlTag, "<$1></$2>" ) + wrap[2];

					// Descend through wrappers to the right content
					j = wrap[0];
					while ( j-- ) {
						tmp = tmp.lastChild;
					}

					// Manually add leading whitespace removed by IE
					if ( !support.leadingWhitespace && rleadingWhitespace.test( elem ) ) {
						nodes.push( context.createTextNode( rleadingWhitespace.exec( elem )[0] ) );
					}

					// Remove IE's autoinserted <tbody> from table fragments
					if ( !support.tbody ) {

						// String was a <table>, *may* have spurious <tbody>
						elem = tag === "table" && !rtbody.test( elem ) ?
							tmp.firstChild :

							// String was a bare <thead> or <tfoot>
							wrap[1] === "<table>" && !rtbody.test( elem ) ?
								tmp :
								0;

						j = elem && elem.childNodes.length;
						while ( j-- ) {
							if ( jQuery.nodeName( (tbody = elem.childNodes[j]), "tbody" ) && !tbody.childNodes.length ) {
								elem.removeChild( tbody );
							}
						}
					}

					jQuery.merge( nodes, tmp.childNodes );

					// Fix #12392 for WebKit and IE > 9
					tmp.textContent = "";

					// Fix #12392 for oldIE
					while ( tmp.firstChild ) {
						tmp.removeChild( tmp.firstChild );
					}

					// Remember the top-level container for proper cleanup
					tmp = safe.lastChild;
				}
			}
		}

		// Fix #11356: Clear elements from fragment
		if ( tmp ) {
			safe.removeChild( tmp );
		}

		// Reset defaultChecked for any radios and checkboxes
		// about to be appended to the DOM in IE 6/7 (#8060)
		if ( !support.appendChecked ) {
			jQuery.grep( getAll( nodes, "input" ), fixDefaultChecked );
		}

		i = 0;
		while ( (elem = nodes[ i++ ]) ) {

			// #4087 - If origin and destination elements are the same, and this is
			// that element, do not do anything
			if ( selection && jQuery.inArray( elem, selection ) !== -1 ) {
				continue;
			}

			contains = jQuery.contains( elem.ownerDocument, elem );

			// Append to fragment
			tmp = getAll( safe.appendChild( elem ), "script" );

			// Preserve script evaluation history
			if ( contains ) {
				setGlobalEval( tmp );
			}

			// Capture executables
			if ( scripts ) {
				j = 0;
				while ( (elem = tmp[ j++ ]) ) {
					if ( rscriptType.test( elem.type || "" ) ) {
						scripts.push( elem );
					}
				}
			}
		}

		tmp = null;

		return safe;
	},

	cleanData: function( elems, /* internal */ acceptData ) {
		var elem, type, id, data,
			i = 0,
			internalKey = jQuery.expando,
			cache = jQuery.cache,
			deleteExpando = support.deleteExpando,
			special = jQuery.event.special;

		for ( ; (elem = elems[i]) != null; i++ ) {
			if ( acceptData || jQuery.acceptData( elem ) ) {

				id = elem[ internalKey ];
				data = id && cache[ id ];

				if ( data ) {
					if ( data.events ) {
						for ( type in data.events ) {
							if ( special[ type ] ) {
								jQuery.event.remove( elem, type );

							// This is a shortcut to avoid jQuery.event.remove's overhead
							} else {
								jQuery.removeEvent( elem, type, data.handle );
							}
						}
					}

					// Remove cache only if it was not already removed by jQuery.event.remove
					if ( cache[ id ] ) {

						delete cache[ id ];

						// IE does not allow us to delete expando properties from nodes,
						// nor does it have a removeAttribute function on Document nodes;
						// we must handle all of these cases
						if ( deleteExpando ) {
							delete elem[ internalKey ];

						} else if ( typeof elem.removeAttribute !== strundefined ) {
							elem.removeAttribute( internalKey );

						} else {
							elem[ internalKey ] = null;
						}

						deletedIds.push( id );
					}
				}
			}
		}
	}
});

jQuery.fn.extend({
	text: function( value ) {
		return access( this, function( value ) {
			return value === undefined ?
				jQuery.text( this ) :
				this.empty().append( ( this[0] && this[0].ownerDocument || document ).createTextNode( value ) );
		}, null, value, arguments.length );
	},

	append: function() {
		return this.domManip( arguments, function( elem ) {
			if ( this.nodeType === 1 || this.nodeType === 11 || this.nodeType === 9 ) {
				var target = manipulationTarget( this, elem );
				target.appendChild( elem );
			}
		});
	},

	prepend: function() {
		return this.domManip( arguments, function( elem ) {
			if ( this.nodeType === 1 || this.nodeType === 11 || this.nodeType === 9 ) {
				var target = manipulationTarget( this, elem );
				target.insertBefore( elem, target.firstChild );
			}
		});
	},

	before: function() {
		return this.domManip( arguments, function( elem ) {
			if ( this.parentNode ) {
				this.parentNode.insertBefore( elem, this );
			}
		});
	},

	after: function() {
		return this.domManip( arguments, function( elem ) {
			if ( this.parentNode ) {
				this.parentNode.insertBefore( elem, this.nextSibling );
			}
		});
	},

	remove: function( selector, keepData /* Internal Use Only */ ) {
		var elem,
			elems = selector ? jQuery.filter( selector, this ) : this,
			i = 0;

		for ( ; (elem = elems[i]) != null; i++ ) {

			if ( !keepData && elem.nodeType === 1 ) {
				jQuery.cleanData( getAll( elem ) );
			}

			if ( elem.parentNode ) {
				if ( keepData && jQuery.contains( elem.ownerDocument, elem ) ) {
					setGlobalEval( getAll( elem, "script" ) );
				}
				elem.parentNode.removeChild( elem );
			}
		}

		return this;
	},

	empty: function() {
		var elem,
			i = 0;

		for ( ; (elem = this[i]) != null; i++ ) {
			// Remove element nodes and prevent memory leaks
			if ( elem.nodeType === 1 ) {
				jQuery.cleanData( getAll( elem, false ) );
			}

			// Remove any remaining nodes
			while ( elem.firstChild ) {
				elem.removeChild( elem.firstChild );
			}

			// If this is a select, ensure that it displays empty (#12336)
			// Support: IE<9
			if ( elem.options && jQuery.nodeName( elem, "select" ) ) {
				elem.options.length = 0;
			}
		}

		return this;
	},

	clone: function( dataAndEvents, deepDataAndEvents ) {
		dataAndEvents = dataAndEvents == null ? false : dataAndEvents;
		deepDataAndEvents = deepDataAndEvents == null ? dataAndEvents : deepDataAndEvents;

		return this.map(function() {
			return jQuery.clone( this, dataAndEvents, deepDataAndEvents );
		});
	},

	html: function( value ) {
		return access( this, function( value ) {
			var elem = this[ 0 ] || {},
				i = 0,
				l = this.length;

			if ( value === undefined ) {
				return elem.nodeType === 1 ?
					elem.innerHTML.replace( rinlinejQuery, "" ) :
					undefined;
			}

			// See if we can take a shortcut and just use innerHTML
			if ( typeof value === "string" && !rnoInnerhtml.test( value ) &&
				( support.htmlSerialize || !rnoshimcache.test( value )  ) &&
				( support.leadingWhitespace || !rleadingWhitespace.test( value ) ) &&
				!wrapMap[ (rtagName.exec( value ) || [ "", "" ])[ 1 ].toLowerCase() ] ) {

				value = value.replace( rxhtmlTag, "<$1></$2>" );

				try {
					for (; i < l; i++ ) {
						// Remove element nodes and prevent memory leaks
						elem = this[i] || {};
						if ( elem.nodeType === 1 ) {
							jQuery.cleanData( getAll( elem, false ) );
							elem.innerHTML = value;
						}
					}

					elem = 0;

				// If using innerHTML throws an exception, use the fallback method
				} catch(e) {}
			}

			if ( elem ) {
				this.empty().append( value );
			}
		}, null, value, arguments.length );
	},

	replaceWith: function() {
		var arg = arguments[ 0 ];

		// Make the changes, replacing each context element with the new content
		this.domManip( arguments, function( elem ) {
			arg = this.parentNode;

			jQuery.cleanData( getAll( this ) );

			if ( arg ) {
				arg.replaceChild( elem, this );
			}
		});

		// Force removal if there was no new content (e.g., from empty arguments)
		return arg && (arg.length || arg.nodeType) ? this : this.remove();
	},

	detach: function( selector ) {
		return this.remove( selector, true );
	},

	domManip: function( args, callback ) {

		// Flatten any nested arrays
		args = concat.apply( [], args );

		var first, node, hasScripts,
			scripts, doc, fragment,
			i = 0,
			l = this.length,
			set = this,
			iNoClone = l - 1,
			value = args[0],
			isFunction = jQuery.isFunction( value );

		// We can't cloneNode fragments that contain checked, in WebKit
		if ( isFunction ||
				( l > 1 && typeof value === "string" &&
					!support.checkClone && rchecked.test( value ) ) ) {
			return this.each(function( index ) {
				var self = set.eq( index );
				if ( isFunction ) {
					args[0] = value.call( this, index, self.html() );
				}
				self.domManip( args, callback );
			});
		}

		if ( l ) {
			fragment = jQuery.buildFragment( args, this[ 0 ].ownerDocument, false, this );
			first = fragment.firstChild;

			if ( fragment.childNodes.length === 1 ) {
				fragment = first;
			}

			if ( first ) {
				scripts = jQuery.map( getAll( fragment, "script" ), disableScript );
				hasScripts = scripts.length;

				// Use the original fragment for the last item instead of the first because it can end up
				// being emptied incorrectly in certain situations (#8070).
				for ( ; i < l; i++ ) {
					node = fragment;

					if ( i !== iNoClone ) {
						node = jQuery.clone( node, true, true );

						// Keep references to cloned scripts for later restoration
						if ( hasScripts ) {
							jQuery.merge( scripts, getAll( node, "script" ) );
						}
					}

					callback.call( this[i], node, i );
				}

				if ( hasScripts ) {
					doc = scripts[ scripts.length - 1 ].ownerDocument;

					// Reenable scripts
					jQuery.map( scripts, restoreScript );

					// Evaluate executable scripts on first document insertion
					for ( i = 0; i < hasScripts; i++ ) {
						node = scripts[ i ];
						if ( rscriptType.test( node.type || "" ) &&
							!jQuery._data( node, "globalEval" ) && jQuery.contains( doc, node ) ) {

							if ( node.src ) {
								// Optional AJAX dependency, but won't run scripts if not present
								if ( jQuery._evalUrl ) {
									jQuery._evalUrl( node.src );
								}
							} else {
								jQuery.globalEval( ( node.text || node.textContent || node.innerHTML || "" ).replace( rcleanScript, "" ) );
							}
						}
					}
				}

				// Fix #11809: Avoid leaking memory
				fragment = first = null;
			}
		}

		return this;
	}
});

jQuery.each({
	appendTo: "append",
	prependTo: "prepend",
	insertBefore: "before",
	insertAfter: "after",
	replaceAll: "replaceWith"
}, function( name, original ) {
	jQuery.fn[ name ] = function( selector ) {
		var elems,
			i = 0,
			ret = [],
			insert = jQuery( selector ),
			last = insert.length - 1;

		for ( ; i <= last; i++ ) {
			elems = i === last ? this : this.clone(true);
			jQuery( insert[i] )[ original ]( elems );

			// Modern browsers can apply jQuery collections as arrays, but oldIE needs a .get()
			push.apply( ret, elems.get() );
		}

		return this.pushStack( ret );
	};
});


var iframe,
	elemdisplay = {};

/**
 * Retrieve the actual display of a element
 * @param {String} name nodeName of the element
 * @param {Object} doc Document object
 */
// Called only from within defaultDisplay
function actualDisplay( name, doc ) {
	var style,
		elem = jQuery( doc.createElement( name ) ).appendTo( doc.body ),

		// getDefaultComputedStyle might be reliably used only on attached element
		display = window.getDefaultComputedStyle && ( style = window.getDefaultComputedStyle( elem[ 0 ] ) ) ?

			// Use of this method is a temporary fix (more like optmization) until something better comes along,
			// since it was removed from specification and supported only in FF
			style.display : jQuery.css( elem[ 0 ], "display" );

	// We don't have any data stored on the element,
	// so use "detach" method as fast way to get rid of the element
	elem.detach();

	return display;
}

/**
 * Try to determine the default display value of an element
 * @param {String} nodeName
 */
function defaultDisplay( nodeName ) {
	var doc = document,
		display = elemdisplay[ nodeName ];

	if ( !display ) {
		display = actualDisplay( nodeName, doc );

		// If the simple way fails, read from inside an iframe
		if ( display === "none" || !display ) {

			// Use the already-created iframe if possible
			iframe = (iframe || jQuery( "<iframe frameborder='0' width='0' height='0'/>" )).appendTo( doc.documentElement );

			// Always write a new HTML skeleton so Webkit and Firefox don't choke on reuse
			doc = ( iframe[ 0 ].contentWindow || iframe[ 0 ].contentDocument ).document;

			// Support: IE
			doc.write();
			doc.close();

			display = actualDisplay( nodeName, doc );
			iframe.detach();
		}

		// Store the correct default display
		elemdisplay[ nodeName ] = display;
	}

	return display;
}


(function() {
	var shrinkWrapBlocksVal;

	support.shrinkWrapBlocks = function() {
		if ( shrinkWrapBlocksVal != null ) {
			return shrinkWrapBlocksVal;
		}

		// Will be changed later if needed.
		shrinkWrapBlocksVal = false;

		// Minified: var b,c,d
		var div, body, container;

		body = document.getElementsByTagName( "body" )[ 0 ];
		if ( !body || !body.style ) {
			// Test fired too early or in an unsupported environment, exit.
			return;
		}

		// Setup
		div = document.createElement( "div" );
		container = document.createElement( "div" );
		container.style.cssText = "position:absolute;border:0;width:0;height:0;top:0;left:-9999px";
		body.appendChild( container ).appendChild( div );

		// Support: IE6
		// Check if elements with layout shrink-wrap their children
		if ( typeof div.style.zoom !== strundefined ) {
			// Reset CSS: box-sizing; display; margin; border
			div.style.cssText =
				// Support: Firefox<29, Android 2.3
				// Vendor-prefix box-sizing
				"-webkit-box-sizing:content-box;-moz-box-sizing:content-box;" +
				"box-sizing:content-box;display:block;margin:0;border:0;" +
				"padding:1px;width:1px;zoom:1";
			div.appendChild( document.createElement( "div" ) ).style.width = "5px";
			shrinkWrapBlocksVal = div.offsetWidth !== 3;
		}

		body.removeChild( container );

		return shrinkWrapBlocksVal;
	};

})();
var rmargin = (/^margin/);

var rnumnonpx = new RegExp( "^(" + pnum + ")(?!px)[a-z%]+$", "i" );



var getStyles, curCSS,
	rposition = /^(top|right|bottom|left)$/;

if ( window.getComputedStyle ) {
	getStyles = function( elem ) {
		// Support: IE<=11+, Firefox<=30+ (#15098, #14150)
		// IE throws on elements created in popups
		// FF meanwhile throws on frame elements through "defaultView.getComputedStyle"
		if ( elem.ownerDocument.defaultView.opener ) {
			return elem.ownerDocument.defaultView.getComputedStyle( elem, null );
		}

		return window.getComputedStyle( elem, null );
	};

	curCSS = function( elem, name, computed ) {
		var width, minWidth, maxWidth, ret,
			style = elem.style;

		computed = computed || getStyles( elem );

		// getPropertyValue is only needed for .css('filter') in IE9, see #12537
		ret = computed ? computed.getPropertyValue( name ) || computed[ name ] : undefined;

		if ( computed ) {

			if ( ret === "" && !jQuery.contains( elem.ownerDocument, elem ) ) {
				ret = jQuery.style( elem, name );
			}

			// A tribute to the "awesome hack by Dean Edwards"
			// Chrome < 17 and Safari 5.0 uses "computed value" instead of "used value" for margin-right
			// Safari 5.1.7 (at least) returns percentage for a larger set of values, but width seems to be reliably pixels
			// this is against the CSSOM draft spec: http://dev.w3.org/csswg/cssom/#resolved-values
			if ( rnumnonpx.test( ret ) && rmargin.test( name ) ) {

				// Remember the original values
				width = style.width;
				minWidth = style.minWidth;
				maxWidth = style.maxWidth;

				// Put in the new values to get a computed value out
				style.minWidth = style.maxWidth = style.width = ret;
				ret = computed.width;

				// Revert the changed values
				style.width = width;
				style.minWidth = minWidth;
				style.maxWidth = maxWidth;
			}
		}

		// Support: IE
		// IE returns zIndex value as an integer.
		return ret === undefined ?
			ret :
			ret + "";
	};
} else if ( document.documentElement.currentStyle ) {
	getStyles = function( elem ) {
		return elem.currentStyle;
	};

	curCSS = function( elem, name, computed ) {
		var left, rs, rsLeft, ret,
			style = elem.style;

		computed = computed || getStyles( elem );
		ret = computed ? computed[ name ] : undefined;

		// Avoid setting ret to empty string here
		// so we don't default to auto
		if ( ret == null && style && style[ name ] ) {
			ret = style[ name ];
		}

		// From the awesome hack by Dean Edwards
		// http://erik.eae.net/archives/2007/07/27/18.54.15/#comment-102291

		// If we're not dealing with a regular pixel number
		// but a number that has a weird ending, we need to convert it to pixels
		// but not position css attributes, as those are proportional to the parent element instead
		// and we can't measure the parent instead because it might trigger a "stacking dolls" problem
		if ( rnumnonpx.test( ret ) && !rposition.test( name ) ) {

			// Remember the original values
			left = style.left;
			rs = elem.runtimeStyle;
			rsLeft = rs && rs.left;

			// Put in the new values to get a computed value out
			if ( rsLeft ) {
				rs.left = elem.currentStyle.left;
			}
			style.left = name === "fontSize" ? "1em" : ret;
			ret = style.pixelLeft + "px";

			// Revert the changed values
			style.left = left;
			if ( rsLeft ) {
				rs.left = rsLeft;
			}
		}

		// Support: IE
		// IE returns zIndex value as an integer.
		return ret === undefined ?
			ret :
			ret + "" || "auto";
	};
}




function addGetHookIf( conditionFn, hookFn ) {
	// Define the hook, we'll check on the first run if it's really needed.
	return {
		get: function() {
			var condition = conditionFn();

			if ( condition == null ) {
				// The test was not ready at this point; screw the hook this time
				// but check again when needed next time.
				return;
			}

			if ( condition ) {
				// Hook not needed (or it's not possible to use it due to missing dependency),
				// remove it.
				// Since there are no other hooks for marginRight, remove the whole object.
				delete this.get;
				return;
			}

			// Hook needed; redefine it so that the support test is not executed again.

			return (this.get = hookFn).apply( this, arguments );
		}
	};
}


(function() {
	// Minified: var b,c,d,e,f,g, h,i
	var div, style, a, pixelPositionVal, boxSizingReliableVal,
		reliableHiddenOffsetsVal, reliableMarginRightVal;

	// Setup
	div = document.createElement( "div" );
	div.innerHTML = "  <link/><table></table><a href='/a'>a</a><input type='checkbox'/>";
	a = div.getElementsByTagName( "a" )[ 0 ];
	style = a && a.style;

	// Finish early in limited (non-browser) environments
	if ( !style ) {
		return;
	}

	style.cssText = "float:left;opacity:.5";

	// Support: IE<9
	// Make sure that element opacity exists (as opposed to filter)
	support.opacity = style.opacity === "0.5";

	// Verify style float existence
	// (IE uses styleFloat instead of cssFloat)
	support.cssFloat = !!style.cssFloat;

	div.style.backgroundClip = "content-box";
	div.cloneNode( true ).style.backgroundClip = "";
	support.clearCloneStyle = div.style.backgroundClip === "content-box";

	// Support: Firefox<29, Android 2.3
	// Vendor-prefix box-sizing
	support.boxSizing = style.boxSizing === "" || style.MozBoxSizing === "" ||
		style.WebkitBoxSizing === "";

	jQuery.extend(support, {
		reliableHiddenOffsets: function() {
			if ( reliableHiddenOffsetsVal == null ) {
				computeStyleTests();
			}
			return reliableHiddenOffsetsVal;
		},

		boxSizingReliable: function() {
			if ( boxSizingReliableVal == null ) {
				computeStyleTests();
			}
			return boxSizingReliableVal;
		},

		pixelPosition: function() {
			if ( pixelPositionVal == null ) {
				computeStyleTests();
			}
			return pixelPositionVal;
		},

		// Support: Android 2.3
		reliableMarginRight: function() {
			if ( reliableMarginRightVal == null ) {
				computeStyleTests();
			}
			return reliableMarginRightVal;
		}
	});

	function computeStyleTests() {
		// Minified: var b,c,d,j
		var div, body, container, contents;

		body = document.getElementsByTagName( "body" )[ 0 ];
		if ( !body || !body.style ) {
			// Test fired too early or in an unsupported environment, exit.
			return;
		}

		// Setup
		div = document.createElement( "div" );
		container = document.createElement( "div" );
		container.style.cssText = "position:absolute;border:0;width:0;height:0;top:0;left:-9999px";
		body.appendChild( container ).appendChild( div );

		div.style.cssText =
			// Support: Firefox<29, Android 2.3
			// Vendor-prefix box-sizing
			"-webkit-box-sizing:border-box;-moz-box-sizing:border-box;" +
			"box-sizing:border-box;display:block;margin-top:1%;top:1%;" +
			"border:1px;padding:1px;width:4px;position:absolute";

		// Support: IE<9
		// Assume reasonable values in the absence of getComputedStyle
		pixelPositionVal = boxSizingReliableVal = false;
		reliableMarginRightVal = true;

		// Check for getComputedStyle so that this code is not run in IE<9.
		if ( window.getComputedStyle ) {
			pixelPositionVal = ( window.getComputedStyle( div, null ) || {} ).top !== "1%";
			boxSizingReliableVal =
				( window.getComputedStyle( div, null ) || { width: "4px" } ).width === "4px";

			// Support: Android 2.3
			// Div with explicit width and no margin-right incorrectly
			// gets computed margin-right based on width of container (#3333)
			// WebKit Bug 13343 - getComputedStyle returns wrong value for margin-right
			contents = div.appendChild( document.createElement( "div" ) );

			// Reset CSS: box-sizing; display; margin; border; padding
			contents.style.cssText = div.style.cssText =
				// Support: Firefox<29, Android 2.3
				// Vendor-prefix box-sizing
				"-webkit-box-sizing:content-box;-moz-box-sizing:content-box;" +
				"box-sizing:content-box;display:block;margin:0;border:0;padding:0";
			contents.style.marginRight = contents.style.width = "0";
			div.style.width = "1px";

			reliableMarginRightVal =
				!parseFloat( ( window.getComputedStyle( contents, null ) || {} ).marginRight );

			div.removeChild( contents );
		}

		// Support: IE8
		// Check if table cells still have offsetWidth/Height when they are set
		// to display:none and there are still other visible table cells in a
		// table row; if so, offsetWidth/Height are not reliable for use when
		// determining if an element has been hidden directly using
		// display:none (it is still safe to use offsets if a parent element is
		// hidden; don safety goggles and see bug #4512 for more information).
		div.innerHTML = "<table><tr><td></td><td>t</td></tr></table>";
		contents = div.getElementsByTagName( "td" );
		contents[ 0 ].style.cssText = "margin:0;border:0;padding:0;display:none";
		reliableHiddenOffsetsVal = contents[ 0 ].offsetHeight === 0;
		if ( reliableHiddenOffsetsVal ) {
			contents[ 0 ].style.display = "";
			contents[ 1 ].style.display = "none";
			reliableHiddenOffsetsVal = contents[ 0 ].offsetHeight === 0;
		}

		body.removeChild( container );
	}

})();


// A method for quickly swapping in/out CSS properties to get correct calculations.
jQuery.swap = function( elem, options, callback, args ) {
	var ret, name,
		old = {};

	// Remember the old values, and insert the new ones
	for ( name in options ) {
		old[ name ] = elem.style[ name ];
		elem.style[ name ] = options[ name ];
	}

	ret = callback.apply( elem, args || [] );

	// Revert the old values
	for ( name in options ) {
		elem.style[ name ] = old[ name ];
	}

	return ret;
};


var
		ralpha = /alpha\([^)]*\)/i,
	ropacity = /opacity\s*=\s*([^)]*)/,

	// swappable if display is none or starts with table except "table", "table-cell", or "table-caption"
	// see here for display values: https://developer.mozilla.org/en-US/docs/CSS/display
	rdisplayswap = /^(none|table(?!-c[ea]).+)/,
	rnumsplit = new RegExp( "^(" + pnum + ")(.*)$", "i" ),
	rrelNum = new RegExp( "^([+-])=(" + pnum + ")", "i" ),

	cssShow = { position: "absolute", visibility: "hidden", display: "block" },
	cssNormalTransform = {
		letterSpacing: "0",
		fontWeight: "400"
	},

	cssPrefixes = [ "Webkit", "O", "Moz", "ms" ];


// return a css property mapped to a potentially vendor prefixed property
function vendorPropName( style, name ) {

	// shortcut for names that are not vendor prefixed
	if ( name in style ) {
		return name;
	}

	// check for vendor prefixed names
	var capName = name.charAt(0).toUpperCase() + name.slice(1),
		origName = name,
		i = cssPrefixes.length;

	while ( i-- ) {
		name = cssPrefixes[ i ] + capName;
		if ( name in style ) {
			return name;
		}
	}

	return origName;
}

function showHide( elements, show ) {
	var display, elem, hidden,
		values = [],
		index = 0,
		length = elements.length;

	for ( ; index < length; index++ ) {
		elem = elements[ index ];
		if ( !elem.style ) {
			continue;
		}

		values[ index ] = jQuery._data( elem, "olddisplay" );
		display = elem.style.display;
		if ( show ) {
			// Reset the inline display of this element to learn if it is
			// being hidden by cascaded rules or not
			if ( !values[ index ] && display === "none" ) {
				elem.style.display = "";
			}

			// Set elements which have been overridden with display: none
			// in a stylesheet to whatever the default browser style is
			// for such an element
			if ( elem.style.display === "" && isHidden( elem ) ) {
				values[ index ] = jQuery._data( elem, "olddisplay", defaultDisplay(elem.nodeName) );
			}
		} else {
			hidden = isHidden( elem );

			if ( display && display !== "none" || !hidden ) {
				jQuery._data( elem, "olddisplay", hidden ? display : jQuery.css( elem, "display" ) );
			}
		}
	}

	// Set the display of most of the elements in a second loop
	// to avoid the constant reflow
	for ( index = 0; index < length; index++ ) {
		elem = elements[ index ];
		if ( !elem.style ) {
			continue;
		}
		if ( !show || elem.style.display === "none" || elem.style.display === "" ) {
			elem.style.display = show ? values[ index ] || "" : "none";
		}
	}

	return elements;
}

function setPositiveNumber( elem, value, subtract ) {
	var matches = rnumsplit.exec( value );
	return matches ?
		// Guard against undefined "subtract", e.g., when used as in cssHooks
		Math.max( 0, matches[ 1 ] - ( subtract || 0 ) ) + ( matches[ 2 ] || "px" ) :
		value;
}

function augmentWidthOrHeight( elem, name, extra, isBorderBox, styles ) {
	var i = extra === ( isBorderBox ? "border" : "content" ) ?
		// If we already have the right measurement, avoid augmentation
		4 :
		// Otherwise initialize for horizontal or vertical properties
		name === "width" ? 1 : 0,

		val = 0;

	for ( ; i < 4; i += 2 ) {
		// both box models exclude margin, so add it if we want it
		if ( extra === "margin" ) {
			val += jQuery.css( elem, extra + cssExpand[ i ], true, styles );
		}

		if ( isBorderBox ) {
			// border-box includes padding, so remove it if we want content
			if ( extra === "content" ) {
				val -= jQuery.css( elem, "padding" + cssExpand[ i ], true, styles );
			}

			// at this point, extra isn't border nor margin, so remove border
			if ( extra !== "margin" ) {
				val -= jQuery.css( elem, "border" + cssExpand[ i ] + "Width", true, styles );
			}
		} else {
			// at this point, extra isn't content, so add padding
			val += jQuery.css( elem, "padding" + cssExpand[ i ], true, styles );

			// at this point, extra isn't content nor padding, so add border
			if ( extra !== "padding" ) {
				val += jQuery.css( elem, "border" + cssExpand[ i ] + "Width", true, styles );
			}
		}
	}

	return val;
}

function getWidthOrHeight( elem, name, extra ) {

	// Start with offset property, which is equivalent to the border-box value
	var valueIsBorderBox = true,
		val = name === "width" ? elem.offsetWidth : elem.offsetHeight,
		styles = getStyles( elem ),
		isBorderBox = support.boxSizing && jQuery.css( elem, "boxSizing", false, styles ) === "border-box";

	// some non-html elements return undefined for offsetWidth, so check for null/undefined
	// svg - https://bugzilla.mozilla.org/show_bug.cgi?id=649285
	// MathML - https://bugzilla.mozilla.org/show_bug.cgi?id=491668
	if ( val <= 0 || val == null ) {
		// Fall back to computed then uncomputed css if necessary
		val = curCSS( elem, name, styles );
		if ( val < 0 || val == null ) {
			val = elem.style[ name ];
		}

		// Computed unit is not pixels. Stop here and return.
		if ( rnumnonpx.test(val) ) {
			return val;
		}

		// we need the check for style in case a browser which returns unreliable values
		// for getComputedStyle silently falls back to the reliable elem.style
		valueIsBorderBox = isBorderBox && ( support.boxSizingReliable() || val === elem.style[ name ] );

		// Normalize "", auto, and prepare for extra
		val = parseFloat( val ) || 0;
	}

	// use the active box-sizing model to add/subtract irrelevant styles
	return ( val +
		augmentWidthOrHeight(
			elem,
			name,
			extra || ( isBorderBox ? "border" : "content" ),
			valueIsBorderBox,
			styles
		)
	) + "px";
}

jQuery.extend({
	// Add in style property hooks for overriding the default
	// behavior of getting and setting a style property
	cssHooks: {
		opacity: {
			get: function( elem, computed ) {
				if ( computed ) {
					// We should always get a number back from opacity
					var ret = curCSS( elem, "opacity" );
					return ret === "" ? "1" : ret;
				}
			}
		}
	},

	// Don't automatically add "px" to these possibly-unitless properties
	cssNumber: {
		"columnCount": true,
		"fillOpacity": true,
		"flexGrow": true,
		"flexShrink": true,
		"fontWeight": true,
		"lineHeight": true,
		"opacity": true,
		"order": true,
		"orphans": true,
		"widows": true,
		"zIndex": true,
		"zoom": true
	},

	// Add in properties whose names you wish to fix before
	// setting or getting the value
	cssProps: {
		// normalize float css property
		"float": support.cssFloat ? "cssFloat" : "styleFloat"
	},

	// Get and set the style property on a DOM Node
	style: function( elem, name, value, extra ) {
		// Don't set styles on text and comment nodes
		if ( !elem || elem.nodeType === 3 || elem.nodeType === 8 || !elem.style ) {
			return;
		}

		// Make sure that we're working with the right name
		var ret, type, hooks,
			origName = jQuery.camelCase( name ),
			style = elem.style;

		name = jQuery.cssProps[ origName ] || ( jQuery.cssProps[ origName ] = vendorPropName( style, origName ) );

		// gets hook for the prefixed version
		// followed by the unprefixed version
		hooks = jQuery.cssHooks[ name ] || jQuery.cssHooks[ origName ];

		// Check if we're setting a value
		if ( value !== undefined ) {
			type = typeof value;

			// convert relative number strings (+= or -=) to relative numbers. #7345
			if ( type === "string" && (ret = rrelNum.exec( value )) ) {
				value = ( ret[1] + 1 ) * ret[2] + parseFloat( jQuery.css( elem, name ) );
				// Fixes bug #9237
				type = "number";
			}

			// Make sure that null and NaN values aren't set. See: #7116
			if ( value == null || value !== value ) {
				return;
			}

			// If a number was passed in, add 'px' to the (except for certain CSS properties)
			if ( type === "number" && !jQuery.cssNumber[ origName ] ) {
				value += "px";
			}

			// Fixes #8908, it can be done more correctly by specifing setters in cssHooks,
			// but it would mean to define eight (for every problematic property) identical functions
			if ( !support.clearCloneStyle && value === "" && name.indexOf("background") === 0 ) {
				style[ name ] = "inherit";
			}

			// If a hook was provided, use that value, otherwise just set the specified value
			if ( !hooks || !("set" in hooks) || (value = hooks.set( elem, value, extra )) !== undefined ) {

				// Support: IE
				// Swallow errors from 'invalid' CSS values (#5509)
				try {
					style[ name ] = value;
				} catch(e) {}
			}

		} else {
			// If a hook was provided get the non-computed value from there
			if ( hooks && "get" in hooks && (ret = hooks.get( elem, false, extra )) !== undefined ) {
				return ret;
			}

			// Otherwise just get the value from the style object
			return style[ name ];
		}
	},

	css: function( elem, name, extra, styles ) {
		var num, val, hooks,
			origName = jQuery.camelCase( name );

		// Make sure that we're working with the right name
		name = jQuery.cssProps[ origName ] || ( jQuery.cssProps[ origName ] = vendorPropName( elem.style, origName ) );

		// gets hook for the prefixed version
		// followed by the unprefixed version
		hooks = jQuery.cssHooks[ name ] || jQuery.cssHooks[ origName ];

		// If a hook was provided get the computed value from there
		if ( hooks && "get" in hooks ) {
			val = hooks.get( elem, true, extra );
		}

		// Otherwise, if a way to get the computed value exists, use that
		if ( val === undefined ) {
			val = curCSS( elem, name, styles );
		}

		//convert "normal" to computed value
		if ( val === "normal" && name in cssNormalTransform ) {
			val = cssNormalTransform[ name ];
		}

		// Return, converting to number if forced or a qualifier was provided and val looks numeric
		if ( extra === "" || extra ) {
			num = parseFloat( val );
			return extra === true || jQuery.isNumeric( num ) ? num || 0 : val;
		}
		return val;
	}
});

jQuery.each([ "height", "width" ], function( i, name ) {
	jQuery.cssHooks[ name ] = {
		get: function( elem, computed, extra ) {
			if ( computed ) {
				// certain elements can have dimension info if we invisibly show them
				// however, it must have a current display style that would benefit from this
				return rdisplayswap.test( jQuery.css( elem, "display" ) ) && elem.offsetWidth === 0 ?
					jQuery.swap( elem, cssShow, function() {
						return getWidthOrHeight( elem, name, extra );
					}) :
					getWidthOrHeight( elem, name, extra );
			}
		},

		set: function( elem, value, extra ) {
			var styles = extra && getStyles( elem );
			return setPositiveNumber( elem, value, extra ?
				augmentWidthOrHeight(
					elem,
					name,
					extra,
					support.boxSizing && jQuery.css( elem, "boxSizing", false, styles ) === "border-box",
					styles
				) : 0
			);
		}
	};
});

if ( !support.opacity ) {
	jQuery.cssHooks.opacity = {
		get: function( elem, computed ) {
			// IE uses filters for opacity
			return ropacity.test( (computed && elem.currentStyle ? elem.currentStyle.filter : elem.style.filter) || "" ) ?
				( 0.01 * parseFloat( RegExp.$1 ) ) + "" :
				computed ? "1" : "";
		},

		set: function( elem, value ) {
			var style = elem.style,
				currentStyle = elem.currentStyle,
				opacity = jQuery.isNumeric( value ) ? "alpha(opacity=" + value * 100 + ")" : "",
				filter = currentStyle && currentStyle.filter || style.filter || "";

			// IE has trouble with opacity if it does not have layout
			// Force it by setting the zoom level
			style.zoom = 1;

			// if setting opacity to 1, and no other filters exist - attempt to remove filter attribute #6652
			// if value === "", then remove inline opacity #12685
			if ( ( value >= 1 || value === "" ) &&
					jQuery.trim( filter.replace( ralpha, "" ) ) === "" &&
					style.removeAttribute ) {

				// Setting style.filter to null, "" & " " still leave "filter:" in the cssText
				// if "filter:" is present at all, clearType is disabled, we want to avoid this
				// style.removeAttribute is IE Only, but so apparently is this code path...
				style.removeAttribute( "filter" );

				// if there is no filter style applied in a css rule or unset inline opacity, we are done
				if ( value === "" || currentStyle && !currentStyle.filter ) {
					return;
				}
			}

			// otherwise, set new filter values
			style.filter = ralpha.test( filter ) ?
				filter.replace( ralpha, opacity ) :
				filter + " " + opacity;
		}
	};
}

jQuery.cssHooks.marginRight = addGetHookIf( support.reliableMarginRight,
	function( elem, computed ) {
		if ( computed ) {
			// WebKit Bug 13343 - getComputedStyle returns wrong value for margin-right
			// Work around by temporarily setting element display to inline-block
			return jQuery.swap( elem, { "display": "inline-block" },
				curCSS, [ elem, "marginRight" ] );
		}
	}
);

// These hooks are used by animate to expand properties
jQuery.each({
	margin: "",
	padding: "",
	border: "Width"
}, function( prefix, suffix ) {
	jQuery.cssHooks[ prefix + suffix ] = {
		expand: function( value ) {
			var i = 0,
				expanded = {},

				// assumes a single number if not a string
				parts = typeof value === "string" ? value.split(" ") : [ value ];

			for ( ; i < 4; i++ ) {
				expanded[ prefix + cssExpand[ i ] + suffix ] =
					parts[ i ] || parts[ i - 2 ] || parts[ 0 ];
			}

			return expanded;
		}
	};

	if ( !rmargin.test( prefix ) ) {
		jQuery.cssHooks[ prefix + suffix ].set = setPositiveNumber;
	}
});

jQuery.fn.extend({
	css: function( name, value ) {
		return access( this, function( elem, name, value ) {
			var styles, len,
				map = {},
				i = 0;

			if ( jQuery.isArray( name ) ) {
				styles = getStyles( elem );
				len = name.length;

				for ( ; i < len; i++ ) {
					map[ name[ i ] ] = jQuery.css( elem, name[ i ], false, styles );
				}

				return map;
			}

			return value !== undefined ?
				jQuery.style( elem, name, value ) :
				jQuery.css( elem, name );
		}, name, value, arguments.length > 1 );
	},
	show: function() {
		return showHide( this, true );
	},
	hide: function() {
		return showHide( this );
	},
	toggle: function( state ) {
		if ( typeof state === "boolean" ) {
			return state ? this.show() : this.hide();
		}

		return this.each(function() {
			if ( isHidden( this ) ) {
				jQuery( this ).show();
			} else {
				jQuery( this ).hide();
			}
		});
	}
});


function Tween( elem, options, prop, end, easing ) {
	return new Tween.prototype.init( elem, options, prop, end, easing );
}
jQuery.Tween = Tween;

Tween.prototype = {
	constructor: Tween,
	init: function( elem, options, prop, end, easing, unit ) {
		this.elem = elem;
		this.prop = prop;
		this.easing = easing || "swing";
		this.options = options;
		this.start = this.now = this.cur();
		this.end = end;
		this.unit = unit || ( jQuery.cssNumber[ prop ] ? "" : "px" );
	},
	cur: function() {
		var hooks = Tween.propHooks[ this.prop ];

		return hooks && hooks.get ?
			hooks.get( this ) :
			Tween.propHooks._default.get( this );
	},
	run: function( percent ) {
		var eased,
			hooks = Tween.propHooks[ this.prop ];

		if ( this.options.duration ) {
			this.pos = eased = jQuery.easing[ this.easing ](
				percent, this.options.duration * percent, 0, 1, this.options.duration
			);
		} else {
			this.pos = eased = percent;
		}
		this.now = ( this.end - this.start ) * eased + this.start;

		if ( this.options.step ) {
			this.options.step.call( this.elem, this.now, this );
		}

		if ( hooks && hooks.set ) {
			hooks.set( this );
		} else {
			Tween.propHooks._default.set( this );
		}
		return this;
	}
};

Tween.prototype.init.prototype = Tween.prototype;

Tween.propHooks = {
	_default: {
		get: function( tween ) {
			var result;

			if ( tween.elem[ tween.prop ] != null &&
				(!tween.elem.style || tween.elem.style[ tween.prop ] == null) ) {
				return tween.elem[ tween.prop ];
			}

			// passing an empty string as a 3rd parameter to .css will automatically
			// attempt a parseFloat and fallback to a string if the parse fails
			// so, simple values such as "10px" are parsed to Float.
			// complex values such as "rotate(1rad)" are returned as is.
			result = jQuery.css( tween.elem, tween.prop, "" );
			// Empty strings, null, undefined and "auto" are converted to 0.
			return !result || result === "auto" ? 0 : result;
		},
		set: function( tween ) {
			// use step hook for back compat - use cssHook if its there - use .style if its
			// available and use plain properties where available
			if ( jQuery.fx.step[ tween.prop ] ) {
				jQuery.fx.step[ tween.prop ]( tween );
			} else if ( tween.elem.style && ( tween.elem.style[ jQuery.cssProps[ tween.prop ] ] != null || jQuery.cssHooks[ tween.prop ] ) ) {
				jQuery.style( tween.elem, tween.prop, tween.now + tween.unit );
			} else {
				tween.elem[ tween.prop ] = tween.now;
			}
		}
	}
};

// Support: IE <=9
// Panic based approach to setting things on disconnected nodes

Tween.propHooks.scrollTop = Tween.propHooks.scrollLeft = {
	set: function( tween ) {
		if ( tween.elem.nodeType && tween.elem.parentNode ) {
			tween.elem[ tween.prop ] = tween.now;
		}
	}
};

jQuery.easing = {
	linear: function( p ) {
		return p;
	},
	swing: function( p ) {
		return 0.5 - Math.cos( p * Math.PI ) / 2;
	}
};

jQuery.fx = Tween.prototype.init;

// Back Compat <1.8 extension point
jQuery.fx.step = {};




var
	fxNow, timerId,
	rfxtypes = /^(?:toggle|show|hide)$/,
	rfxnum = new RegExp( "^(?:([+-])=|)(" + pnum + ")([a-z%]*)$", "i" ),
	rrun = /queueHooks$/,
	animationPrefilters = [ defaultPrefilter ],
	tweeners = {
		"*": [ function( prop, value ) {
			var tween = this.createTween( prop, value ),
				target = tween.cur(),
				parts = rfxnum.exec( value ),
				unit = parts && parts[ 3 ] || ( jQuery.cssNumber[ prop ] ? "" : "px" ),

				// Starting value computation is required for potential unit mismatches
				start = ( jQuery.cssNumber[ prop ] || unit !== "px" && +target ) &&
					rfxnum.exec( jQuery.css( tween.elem, prop ) ),
				scale = 1,
				maxIterations = 20;

			if ( start && start[ 3 ] !== unit ) {
				// Trust units reported by jQuery.css
				unit = unit || start[ 3 ];

				// Make sure we update the tween properties later on
				parts = parts || [];

				// Iteratively approximate from a nonzero starting point
				start = +target || 1;

				do {
					// If previous iteration zeroed out, double until we get *something*
					// Use a string for doubling factor so we don't accidentally see scale as unchanged below
					scale = scale || ".5";

					// Adjust and apply
					start = start / scale;
					jQuery.style( tween.elem, prop, start + unit );

				// Update scale, tolerating zero or NaN from tween.cur()
				// And breaking the loop if scale is unchanged or perfect, or if we've just had enough
				} while ( scale !== (scale = tween.cur() / target) && scale !== 1 && --maxIterations );
			}

			// Update tween properties
			if ( parts ) {
				start = tween.start = +start || +target || 0;
				tween.unit = unit;
				// If a +=/-= token was provided, we're doing a relative animation
				tween.end = parts[ 1 ] ?
					start + ( parts[ 1 ] + 1 ) * parts[ 2 ] :
					+parts[ 2 ];
			}

			return tween;
		} ]
	};

// Animations created synchronously will run synchronously
function createFxNow() {
	setTimeout(function() {
		fxNow = undefined;
	});
	return ( fxNow = jQuery.now() );
}

// Generate parameters to create a standard animation
function genFx( type, includeWidth ) {
	var which,
		attrs = { height: type },
		i = 0;

	// if we include width, step value is 1 to do all cssExpand values,
	// if we don't include width, step value is 2 to skip over Left and Right
	includeWidth = includeWidth ? 1 : 0;
	for ( ; i < 4 ; i += 2 - includeWidth ) {
		which = cssExpand[ i ];
		attrs[ "margin" + which ] = attrs[ "padding" + which ] = type;
	}

	if ( includeWidth ) {
		attrs.opacity = attrs.width = type;
	}

	return attrs;
}

function createTween( value, prop, animation ) {
	var tween,
		collection = ( tweeners[ prop ] || [] ).concat( tweeners[ "*" ] ),
		index = 0,
		length = collection.length;
	for ( ; index < length; index++ ) {
		if ( (tween = collection[ index ].call( animation, prop, value )) ) {

			// we're done with this property
			return tween;
		}
	}
}

function defaultPrefilter( elem, props, opts ) {
	/* jshint validthis: true */
	var prop, value, toggle, tween, hooks, oldfire, display, checkDisplay,
		anim = this,
		orig = {},
		style = elem.style,
		hidden = elem.nodeType && isHidden( elem ),
		dataShow = jQuery._data( elem, "fxshow" );

	// handle queue: false promises
	if ( !opts.queue ) {
		hooks = jQuery._queueHooks( elem, "fx" );
		if ( hooks.unqueued == null ) {
			hooks.unqueued = 0;
			oldfire = hooks.empty.fire;
			hooks.empty.fire = function() {
				if ( !hooks.unqueued ) {
					oldfire();
				}
			};
		}
		hooks.unqueued++;

		anim.always(function() {
			// doing this makes sure that the complete handler will be called
			// before this completes
			anim.always(function() {
				hooks.unqueued--;
				if ( !jQuery.queue( elem, "fx" ).length ) {
					hooks.empty.fire();
				}
			});
		});
	}

	// height/width overflow pass
	if ( elem.nodeType === 1 && ( "height" in props || "width" in props ) ) {
		// Make sure that nothing sneaks out
		// Record all 3 overflow attributes because IE does not
		// change the overflow attribute when overflowX and
		// overflowY are set to the same value
		opts.overflow = [ style.overflow, style.overflowX, style.overflowY ];

		// Set display property to inline-block for height/width
		// animations on inline elements that are having width/height animated
		display = jQuery.css( elem, "display" );

		// Test default display if display is currently "none"
		checkDisplay = display === "none" ?
			jQuery._data( elem, "olddisplay" ) || defaultDisplay( elem.nodeName ) : display;

		if ( checkDisplay === "inline" && jQuery.css( elem, "float" ) === "none" ) {

			// inline-level elements accept inline-block;
			// block-level elements need to be inline with layout
			if ( !support.inlineBlockNeedsLayout || defaultDisplay( elem.nodeName ) === "inline" ) {
				style.display = "inline-block";
			} else {
				style.zoom = 1;
			}
		}
	}

	if ( opts.overflow ) {
		style.overflow = "hidden";
		if ( !support.shrinkWrapBlocks() ) {
			anim.always(function() {
				style.overflow = opts.overflow[ 0 ];
				style.overflowX = opts.overflow[ 1 ];
				style.overflowY = opts.overflow[ 2 ];
			});
		}
	}

	// show/hide pass
	for ( prop in props ) {
		value = props[ prop ];
		if ( rfxtypes.exec( value ) ) {
			delete props[ prop ];
			toggle = toggle || value === "toggle";
			if ( value === ( hidden ? "hide" : "show" ) ) {

				// If there is dataShow left over from a stopped hide or show and we are going to proceed with show, we should pretend to be hidden
				if ( value === "show" && dataShow && dataShow[ prop ] !== undefined ) {
					hidden = true;
				} else {
					continue;
				}
			}
			orig[ prop ] = dataShow && dataShow[ prop ] || jQuery.style( elem, prop );

		// Any non-fx value stops us from restoring the original display value
		} else {
			display = undefined;
		}
	}

	if ( !jQuery.isEmptyObject( orig ) ) {
		if ( dataShow ) {
			if ( "hidden" in dataShow ) {
				hidden = dataShow.hidden;
			}
		} else {
			dataShow = jQuery._data( elem, "fxshow", {} );
		}

		// store state if its toggle - enables .stop().toggle() to "reverse"
		if ( toggle ) {
			dataShow.hidden = !hidden;
		}
		if ( hidden ) {
			jQuery( elem ).show();
		} else {
			anim.done(function() {
				jQuery( elem ).hide();
			});
		}
		anim.done(function() {
			var prop;
			jQuery._removeData( elem, "fxshow" );
			for ( prop in orig ) {
				jQuery.style( elem, prop, orig[ prop ] );
			}
		});
		for ( prop in orig ) {
			tween = createTween( hidden ? dataShow[ prop ] : 0, prop, anim );

			if ( !( prop in dataShow ) ) {
				dataShow[ prop ] = tween.start;
				if ( hidden ) {
					tween.end = tween.start;
					tween.start = prop === "width" || prop === "height" ? 1 : 0;
				}
			}
		}

	// If this is a noop like .hide().hide(), restore an overwritten display value
	} else if ( (display === "none" ? defaultDisplay( elem.nodeName ) : display) === "inline" ) {
		style.display = display;
	}
}

function propFilter( props, specialEasing ) {
	var index, name, easing, value, hooks;

	// camelCase, specialEasing and expand cssHook pass
	for ( index in props ) {
		name = jQuery.camelCase( index );
		easing = specialEasing[ name ];
		value = props[ index ];
		if ( jQuery.isArray( value ) ) {
			easing = value[ 1 ];
			value = props[ index ] = value[ 0 ];
		}

		if ( index !== name ) {
			props[ name ] = value;
			delete props[ index ];
		}

		hooks = jQuery.cssHooks[ name ];
		if ( hooks && "expand" in hooks ) {
			value = hooks.expand( value );
			delete props[ name ];

			// not quite $.extend, this wont overwrite keys already present.
			// also - reusing 'index' from above because we have the correct "name"
			for ( index in value ) {
				if ( !( index in props ) ) {
					props[ index ] = value[ index ];
					specialEasing[ index ] = easing;
				}
			}
		} else {
			specialEasing[ name ] = easing;
		}
	}
}

function Animation( elem, properties, options ) {
	var result,
		stopped,
		index = 0,
		length = animationPrefilters.length,
		deferred = jQuery.Deferred().always( function() {
			// don't match elem in the :animated selector
			delete tick.elem;
		}),
		tick = function() {
			if ( stopped ) {
				return false;
			}
			var currentTime = fxNow || createFxNow(),
				remaining = Math.max( 0, animation.startTime + animation.duration - currentTime ),
				// archaic crash bug won't allow us to use 1 - ( 0.5 || 0 ) (#12497)
				temp = remaining / animation.duration || 0,
				percent = 1 - temp,
				index = 0,
				length = animation.tweens.length;

			for ( ; index < length ; index++ ) {
				animation.tweens[ index ].run( percent );
			}

			deferred.notifyWith( elem, [ animation, percent, remaining ]);

			if ( percent < 1 && length ) {
				return remaining;
			} else {
				deferred.resolveWith( elem, [ animation ] );
				return false;
			}
		},
		animation = deferred.promise({
			elem: elem,
			props: jQuery.extend( {}, properties ),
			opts: jQuery.extend( true, { specialEasing: {} }, options ),
			originalProperties: properties,
			originalOptions: options,
			startTime: fxNow || createFxNow(),
			duration: options.duration,
			tweens: [],
			createTween: function( prop, end ) {
				var tween = jQuery.Tween( elem, animation.opts, prop, end,
						animation.opts.specialEasing[ prop ] || animation.opts.easing );
				animation.tweens.push( tween );
				return tween;
			},
			stop: function( gotoEnd ) {
				var index = 0,
					// if we are going to the end, we want to run all the tweens
					// otherwise we skip this part
					length = gotoEnd ? animation.tweens.length : 0;
				if ( stopped ) {
					return this;
				}
				stopped = true;
				for ( ; index < length ; index++ ) {
					animation.tweens[ index ].run( 1 );
				}

				// resolve when we played the last frame
				// otherwise, reject
				if ( gotoEnd ) {
					deferred.resolveWith( elem, [ animation, gotoEnd ] );
				} else {
					deferred.rejectWith( elem, [ animation, gotoEnd ] );
				}
				return this;
			}
		}),
		props = animation.props;

	propFilter( props, animation.opts.specialEasing );

	for ( ; index < length ; index++ ) {
		result = animationPrefilters[ index ].call( animation, elem, props, animation.opts );
		if ( result ) {
			return result;
		}
	}

	jQuery.map( props, createTween, animation );

	if ( jQuery.isFunction( animation.opts.start ) ) {
		animation.opts.start.call( elem, animation );
	}

	jQuery.fx.timer(
		jQuery.extend( tick, {
			elem: elem,
			anim: animation,
			queue: animation.opts.queue
		})
	);

	// attach callbacks from options
	return animation.progress( animation.opts.progress )
		.done( animation.opts.done, animation.opts.complete )
		.fail( animation.opts.fail )
		.always( animation.opts.always );
}

jQuery.Animation = jQuery.extend( Animation, {
	tweener: function( props, callback ) {
		if ( jQuery.isFunction( props ) ) {
			callback = props;
			props = [ "*" ];
		} else {
			props = props.split(" ");
		}

		var prop,
			index = 0,
			length = props.length;

		for ( ; index < length ; index++ ) {
			prop = props[ index ];
			tweeners[ prop ] = tweeners[ prop ] || [];
			tweeners[ prop ].unshift( callback );
		}
	},

	prefilter: function( callback, prepend ) {
		if ( prepend ) {
			animationPrefilters.unshift( callback );
		} else {
			animationPrefilters.push( callback );
		}
	}
});

jQuery.speed = function( speed, easing, fn ) {
	var opt = speed && typeof speed === "object" ? jQuery.extend( {}, speed ) : {
		complete: fn || !fn && easing ||
			jQuery.isFunction( speed ) && speed,
		duration: speed,
		easing: fn && easing || easing && !jQuery.isFunction( easing ) && easing
	};

	opt.duration = jQuery.fx.off ? 0 : typeof opt.duration === "number" ? opt.duration :
		opt.duration in jQuery.fx.speeds ? jQuery.fx.speeds[ opt.duration ] : jQuery.fx.speeds._default;

	// normalize opt.queue - true/undefined/null -> "fx"
	if ( opt.queue == null || opt.queue === true ) {
		opt.queue = "fx";
	}

	// Queueing
	opt.old = opt.complete;

	opt.complete = function() {
		if ( jQuery.isFunction( opt.old ) ) {
			opt.old.call( this );
		}

		if ( opt.queue ) {
			jQuery.dequeue( this, opt.queue );
		}
	};

	return opt;
};

jQuery.fn.extend({
	fadeTo: function( speed, to, easing, callback ) {

		// show any hidden elements after setting opacity to 0
		return this.filter( isHidden ).css( "opacity", 0 ).show()

			// animate to the value specified
			.end().animate({ opacity: to }, speed, easing, callback );
	},
	animate: function( prop, speed, easing, callback ) {
		var empty = jQuery.isEmptyObject( prop ),
			optall = jQuery.speed( speed, easing, callback ),
			doAnimation = function() {
				// Operate on a copy of prop so per-property easing won't be lost
				var anim = Animation( this, jQuery.extend( {}, prop ), optall );

				// Empty animations, or finishing resolves immediately
				if ( empty || jQuery._data( this, "finish" ) ) {
					anim.stop( true );
				}
			};
			doAnimation.finish = doAnimation;

		return empty || optall.queue === false ?
			this.each( doAnimation ) :
			this.queue( optall.queue, doAnimation );
	},
	stop: function( type, clearQueue, gotoEnd ) {
		var stopQueue = function( hooks ) {
			var stop = hooks.stop;
			delete hooks.stop;
			stop( gotoEnd );
		};

		if ( typeof type !== "string" ) {
			gotoEnd = clearQueue;
			clearQueue = type;
			type = undefined;
		}
		if ( clearQueue && type !== false ) {
			this.queue( type || "fx", [] );
		}

		return this.each(function() {
			var dequeue = true,
				index = type != null && type + "queueHooks",
				timers = jQuery.timers,
				data = jQuery._data( this );

			if ( index ) {
				if ( data[ index ] && data[ index ].stop ) {
					stopQueue( data[ index ] );
				}
			} else {
				for ( index in data ) {
					if ( data[ index ] && data[ index ].stop && rrun.test( index ) ) {
						stopQueue( data[ index ] );
					}
				}
			}

			for ( index = timers.length; index--; ) {
				if ( timers[ index ].elem === this && (type == null || timers[ index ].queue === type) ) {
					timers[ index ].anim.stop( gotoEnd );
					dequeue = false;
					timers.splice( index, 1 );
				}
			}

			// start the next in the queue if the last step wasn't forced
			// timers currently will call their complete callbacks, which will dequeue
			// but only if they were gotoEnd
			if ( dequeue || !gotoEnd ) {
				jQuery.dequeue( this, type );
			}
		});
	},
	finish: function( type ) {
		if ( type !== false ) {
			type = type || "fx";
		}
		return this.each(function() {
			var index,
				data = jQuery._data( this ),
				queue = data[ type + "queue" ],
				hooks = data[ type + "queueHooks" ],
				timers = jQuery.timers,
				length = queue ? queue.length : 0;

			// enable finishing flag on private data
			data.finish = true;

			// empty the queue first
			jQuery.queue( this, type, [] );

			if ( hooks && hooks.stop ) {
				hooks.stop.call( this, true );
			}

			// look for any active animations, and finish them
			for ( index = timers.length; index--; ) {
				if ( timers[ index ].elem === this && timers[ index ].queue === type ) {
					timers[ index ].anim.stop( true );
					timers.splice( index, 1 );
				}
			}

			// look for any animations in the old queue and finish them
			for ( index = 0; index < length; index++ ) {
				if ( queue[ index ] && queue[ index ].finish ) {
					queue[ index ].finish.call( this );
				}
			}

			// turn off finishing flag
			delete data.finish;
		});
	}
});

jQuery.each([ "toggle", "show", "hide" ], function( i, name ) {
	var cssFn = jQuery.fn[ name ];
	jQuery.fn[ name ] = function( speed, easing, callback ) {
		return speed == null || typeof speed === "boolean" ?
			cssFn.apply( this, arguments ) :
			this.animate( genFx( name, true ), speed, easing, callback );
	};
});

// Generate shortcuts for custom animations
jQuery.each({
	slideDown: genFx("show"),
	slideUp: genFx("hide"),
	slideToggle: genFx("toggle"),
	fadeIn: { opacity: "show" },
	fadeOut: { opacity: "hide" },
	fadeToggle: { opacity: "toggle" }
}, function( name, props ) {
	jQuery.fn[ name ] = function( speed, easing, callback ) {
		return this.animate( props, speed, easing, callback );
	};
});

jQuery.timers = [];
jQuery.fx.tick = function() {
	var timer,
		timers = jQuery.timers,
		i = 0;

	fxNow = jQuery.now();

	for ( ; i < timers.length; i++ ) {
		timer = timers[ i ];
		// Checks the timer has not already been removed
		if ( !timer() && timers[ i ] === timer ) {
			timers.splice( i--, 1 );
		}
	}

	if ( !timers.length ) {
		jQuery.fx.stop();
	}
	fxNow = undefined;
};

jQuery.fx.timer = function( timer ) {
	jQuery.timers.push( timer );
	if ( timer() ) {
		jQuery.fx.start();
	} else {
		jQuery.timers.pop();
	}
};

jQuery.fx.interval = 13;

jQuery.fx.start = function() {
	if ( !timerId ) {
		timerId = setInterval( jQuery.fx.tick, jQuery.fx.interval );
	}
};

jQuery.fx.stop = function() {
	clearInterval( timerId );
	timerId = null;
};

jQuery.fx.speeds = {
	slow: 600,
	fast: 200,
	// Default speed
	_default: 400
};


// Based off of the plugin by Clint Helfers, with permission.
// http://blindsignals.com/index.php/2009/07/jquery-delay/
jQuery.fn.delay = function( time, type ) {
	time = jQuery.fx ? jQuery.fx.speeds[ time ] || time : time;
	type = type || "fx";

	return this.queue( type, function( next, hooks ) {
		var timeout = setTimeout( next, time );
		hooks.stop = function() {
			clearTimeout( timeout );
		};
	});
};


(function() {
	// Minified: var a,b,c,d,e
	var input, div, select, a, opt;

	// Setup
	div = document.createElement( "div" );
	div.setAttribute( "className", "t" );
	div.innerHTML = "  <link/><table></table><a href='/a'>a</a><input type='checkbox'/>";
	a = div.getElementsByTagName("a")[ 0 ];

	// First batch of tests.
	select = document.createElement("select");
	opt = select.appendChild( document.createElement("option") );
	input = div.getElementsByTagName("input")[ 0 ];

	a.style.cssText = "top:1px";

	// Test setAttribute on camelCase class. If it works, we need attrFixes when doing get/setAttribute (ie6/7)
	support.getSetAttribute = div.className !== "t";

	// Get the style information from getAttribute
	// (IE uses .cssText instead)
	support.style = /top/.test( a.getAttribute("style") );

	// Make sure that URLs aren't manipulated
	// (IE normalizes it by default)
	support.hrefNormalized = a.getAttribute("href") === "/a";

	// Check the default checkbox/radio value ("" on WebKit; "on" elsewhere)
	support.checkOn = !!input.value;

	// Make sure that a selected-by-default option has a working selected property.
	// (WebKit defaults to false instead of true, IE too, if it's in an optgroup)
	support.optSelected = opt.selected;

	// Tests for enctype support on a form (#6743)
	support.enctype = !!document.createElement("form").enctype;

	// Make sure that the options inside disabled selects aren't marked as disabled
	// (WebKit marks them as disabled)
	select.disabled = true;
	support.optDisabled = !opt.disabled;

	// Support: IE8 only
	// Check if we can trust getAttribute("value")
	input = document.createElement( "input" );
	input.setAttribute( "value", "" );
	support.input = input.getAttribute( "value" ) === "";

	// Check if an input maintains its value after becoming a radio
	input.value = "t";
	input.setAttribute( "type", "radio" );
	support.radioValue = input.value === "t";
})();


var rreturn = /\r/g;

jQuery.fn.extend({
	val: function( value ) {
		var hooks, ret, isFunction,
			elem = this[0];

		if ( !arguments.length ) {
			if ( elem ) {
				hooks = jQuery.valHooks[ elem.type ] || jQuery.valHooks[ elem.nodeName.toLowerCase() ];

				if ( hooks && "get" in hooks && (ret = hooks.get( elem, "value" )) !== undefined ) {
					return ret;
				}

				ret = elem.value;

				return typeof ret === "string" ?
					// handle most common string cases
					ret.replace(rreturn, "") :
					// handle cases where value is null/undef or number
					ret == null ? "" : ret;
			}

			return;
		}

		isFunction = jQuery.isFunction( value );

		return this.each(function( i ) {
			var val;

			if ( this.nodeType !== 1 ) {
				return;
			}

			if ( isFunction ) {
				val = value.call( this, i, jQuery( this ).val() );
			} else {
				val = value;
			}

			// Treat null/undefined as ""; convert numbers to string
			if ( val == null ) {
				val = "";
			} else if ( typeof val === "number" ) {
				val += "";
			} else if ( jQuery.isArray( val ) ) {
				val = jQuery.map( val, function( value ) {
					return value == null ? "" : value + "";
				});
			}

			hooks = jQuery.valHooks[ this.type ] || jQuery.valHooks[ this.nodeName.toLowerCase() ];

			// If set returns undefined, fall back to normal setting
			if ( !hooks || !("set" in hooks) || hooks.set( this, val, "value" ) === undefined ) {
				this.value = val;
			}
		});
	}
});

jQuery.extend({
	valHooks: {
		option: {
			get: function( elem ) {
				var val = jQuery.find.attr( elem, "value" );
				return val != null ?
					val :
					// Support: IE10-11+
					// option.text throws exceptions (#14686, #14858)
					jQuery.trim( jQuery.text( elem ) );
			}
		},
		select: {
			get: function( elem ) {
				var value, option,
					options = elem.options,
					index = elem.selectedIndex,
					one = elem.type === "select-one" || index < 0,
					values = one ? null : [],
					max = one ? index + 1 : options.length,
					i = index < 0 ?
						max :
						one ? index : 0;

				// Loop through all the selected options
				for ( ; i < max; i++ ) {
					option = options[ i ];

					// oldIE doesn't update selected after form reset (#2551)
					if ( ( option.selected || i === index ) &&
							// Don't return options that are disabled or in a disabled optgroup
							( support.optDisabled ? !option.disabled : option.getAttribute("disabled") === null ) &&
							( !option.parentNode.disabled || !jQuery.nodeName( option.parentNode, "optgroup" ) ) ) {

						// Get the specific value for the option
						value = jQuery( option ).val();

						// We don't need an array for one selects
						if ( one ) {
							return value;
						}

						// Multi-Selects return an array
						values.push( value );
					}
				}

				return values;
			},

			set: function( elem, value ) {
				var optionSet, option,
					options = elem.options,
					values = jQuery.makeArray( value ),
					i = options.length;

				while ( i-- ) {
					option = options[ i ];

					if ( jQuery.inArray( jQuery.valHooks.option.get( option ), values ) >= 0 ) {

						// Support: IE6
						// When new option element is added to select box we need to
						// force reflow of newly added node in order to workaround delay
						// of initialization properties
						try {
							option.selected = optionSet = true;

						} catch ( _ ) {

							// Will be executed only in IE6
							option.scrollHeight;
						}

					} else {
						option.selected = false;
					}
				}

				// Force browsers to behave consistently when non-matching value is set
				if ( !optionSet ) {
					elem.selectedIndex = -1;
				}

				return options;
			}
		}
	}
});

// Radios and checkboxes getter/setter
jQuery.each([ "radio", "checkbox" ], function() {
	jQuery.valHooks[ this ] = {
		set: function( elem, value ) {
			if ( jQuery.isArray( value ) ) {
				return ( elem.checked = jQuery.inArray( jQuery(elem).val(), value ) >= 0 );
			}
		}
	};
	if ( !support.checkOn ) {
		jQuery.valHooks[ this ].get = function( elem ) {
			// Support: Webkit
			// "" is returned instead of "on" if a value isn't specified
			return elem.getAttribute("value") === null ? "on" : elem.value;
		};
	}
});




var nodeHook, boolHook,
	attrHandle = jQuery.expr.attrHandle,
	ruseDefault = /^(?:checked|selected)$/i,
	getSetAttribute = support.getSetAttribute,
	getSetInput = support.input;

jQuery.fn.extend({
	attr: function( name, value ) {
		return access( this, jQuery.attr, name, value, arguments.length > 1 );
	},

	removeAttr: function( name ) {
		return this.each(function() {
			jQuery.removeAttr( this, name );
		});
	}
});

jQuery.extend({
	attr: function( elem, name, value ) {
		var hooks, ret,
			nType = elem.nodeType;

		// don't get/set attributes on text, comment and attribute nodes
		if ( !elem || nType === 3 || nType === 8 || nType === 2 ) {
			return;
		}

		// Fallback to prop when attributes are not supported
		if ( typeof elem.getAttribute === strundefined ) {
			return jQuery.prop( elem, name, value );
		}

		// All attributes are lowercase
		// Grab necessary hook if one is defined
		if ( nType !== 1 || !jQuery.isXMLDoc( elem ) ) {
			name = name.toLowerCase();
			hooks = jQuery.attrHooks[ name ] ||
				( jQuery.expr.match.bool.test( name ) ? boolHook : nodeHook );
		}

		if ( value !== undefined ) {

			if ( value === null ) {
				jQuery.removeAttr( elem, name );

			} else if ( hooks && "set" in hooks && (ret = hooks.set( elem, value, name )) !== undefined ) {
				return ret;

			} else {
				elem.setAttribute( name, value + "" );
				return value;
			}

		} else if ( hooks && "get" in hooks && (ret = hooks.get( elem, name )) !== null ) {
			return ret;

		} else {
			ret = jQuery.find.attr( elem, name );

			// Non-existent attributes return null, we normalize to undefined
			return ret == null ?
				undefined :
				ret;
		}
	},

	removeAttr: function( elem, value ) {
		var name, propName,
			i = 0,
			attrNames = value && value.match( rnotwhite );

		if ( attrNames && elem.nodeType === 1 ) {
			while ( (name = attrNames[i++]) ) {
				propName = jQuery.propFix[ name ] || name;

				// Boolean attributes get special treatment (#10870)
				if ( jQuery.expr.match.bool.test( name ) ) {
					// Set corresponding property to false
					if ( getSetInput && getSetAttribute || !ruseDefault.test( name ) ) {
						elem[ propName ] = false;
					// Support: IE<9
					// Also clear defaultChecked/defaultSelected (if appropriate)
					} else {
						elem[ jQuery.camelCase( "default-" + name ) ] =
							elem[ propName ] = false;
					}

				// See #9699 for explanation of this approach (setting first, then removal)
				} else {
					jQuery.attr( elem, name, "" );
				}

				elem.removeAttribute( getSetAttribute ? name : propName );
			}
		}
	},

	attrHooks: {
		type: {
			set: function( elem, value ) {
				if ( !support.radioValue && value === "radio" && jQuery.nodeName(elem, "input") ) {
					// Setting the type on a radio button after the value resets the value in IE6-9
					// Reset value to default in case type is set after value during creation
					var val = elem.value;
					elem.setAttribute( "type", value );
					if ( val ) {
						elem.value = val;
					}
					return value;
				}
			}
		}
	}
});

// Hook for boolean attributes
boolHook = {
	set: function( elem, value, name ) {
		if ( value === false ) {
			// Remove boolean attributes when set to false
			jQuery.removeAttr( elem, name );
		} else if ( getSetInput && getSetAttribute || !ruseDefault.test( name ) ) {
			// IE<8 needs the *property* name
			elem.setAttribute( !getSetAttribute && jQuery.propFix[ name ] || name, name );

		// Use defaultChecked and defaultSelected for oldIE
		} else {
			elem[ jQuery.camelCase( "default-" + name ) ] = elem[ name ] = true;
		}

		return name;
	}
};

// Retrieve booleans specially
jQuery.each( jQuery.expr.match.bool.source.match( /\w+/g ), function( i, name ) {

	var getter = attrHandle[ name ] || jQuery.find.attr;

	attrHandle[ name ] = getSetInput && getSetAttribute || !ruseDefault.test( name ) ?
		function( elem, name, isXML ) {
			var ret, handle;
			if ( !isXML ) {
				// Avoid an infinite loop by temporarily removing this function from the getter
				handle = attrHandle[ name ];
				attrHandle[ name ] = ret;
				ret = getter( elem, name, isXML ) != null ?
					name.toLowerCase() :
					null;
				attrHandle[ name ] = handle;
			}
			return ret;
		} :
		function( elem, name, isXML ) {
			if ( !isXML ) {
				return elem[ jQuery.camelCase( "default-" + name ) ] ?
					name.toLowerCase() :
					null;
			}
		};
});

// fix oldIE attroperties
if ( !getSetInput || !getSetAttribute ) {
	jQuery.attrHooks.value = {
		set: function( elem, value, name ) {
			if ( jQuery.nodeName( elem, "input" ) ) {
				// Does not return so that setAttribute is also used
				elem.defaultValue = value;
			} else {
				// Use nodeHook if defined (#1954); otherwise setAttribute is fine
				return nodeHook && nodeHook.set( elem, value, name );
			}
		}
	};
}

// IE6/7 do not support getting/setting some attributes with get/setAttribute
if ( !getSetAttribute ) {

	// Use this for any attribute in IE6/7
	// This fixes almost every IE6/7 issue
	nodeHook = {
		set: function( elem, value, name ) {
			// Set the existing or create a new attribute node
			var ret = elem.getAttributeNode( name );
			if ( !ret ) {
				elem.setAttributeNode(
					(ret = elem.ownerDocument.createAttribute( name ))
				);
			}

			ret.value = value += "";

			// Break association with cloned elements by also using setAttribute (#9646)
			if ( name === "value" || value === elem.getAttribute( name ) ) {
				return value;
			}
		}
	};

	// Some attributes are constructed with empty-string values when not defined
	attrHandle.id = attrHandle.name = attrHandle.coords =
		function( elem, name, isXML ) {
			var ret;
			if ( !isXML ) {
				return (ret = elem.getAttributeNode( name )) && ret.value !== "" ?
					ret.value :
					null;
			}
		};

	// Fixing value retrieval on a button requires this module
	jQuery.valHooks.button = {
		get: function( elem, name ) {
			var ret = elem.getAttributeNode( name );
			if ( ret && ret.specified ) {
				return ret.value;
			}
		},
		set: nodeHook.set
	};

	// Set contenteditable to false on removals(#10429)
	// Setting to empty string throws an error as an invalid value
	jQuery.attrHooks.contenteditable = {
		set: function( elem, value, name ) {
			nodeHook.set( elem, value === "" ? false : value, name );
		}
	};

	// Set width and height to auto instead of 0 on empty string( Bug #8150 )
	// This is for removals
	jQuery.each([ "width", "height" ], function( i, name ) {
		jQuery.attrHooks[ name ] = {
			set: function( elem, value ) {
				if ( value === "" ) {
					elem.setAttribute( name, "auto" );
					return value;
				}
			}
		};
	});
}

if ( !support.style ) {
	jQuery.attrHooks.style = {
		get: function( elem ) {
			// Return undefined in the case of empty string
			// Note: IE uppercases css property names, but if we were to .toLowerCase()
			// .cssText, that would destroy case senstitivity in URL's, like in "background"
			return elem.style.cssText || undefined;
		},
		set: function( elem, value ) {
			return ( elem.style.cssText = value + "" );
		}
	};
}




var rfocusable = /^(?:input|select|textarea|button|object)$/i,
	rclickable = /^(?:a|area)$/i;

jQuery.fn.extend({
	prop: function( name, value ) {
		return access( this, jQuery.prop, name, value, arguments.length > 1 );
	},

	removeProp: function( name ) {
		name = jQuery.propFix[ name ] || name;
		return this.each(function() {
			// try/catch handles cases where IE balks (such as removing a property on window)
			try {
				this[ name ] = undefined;
				delete this[ name ];
			} catch( e ) {}
		});
	}
});

jQuery.extend({
	propFix: {
		"for": "htmlFor",
		"class": "className"
	},

	prop: function( elem, name, value ) {
		var ret, hooks, notxml,
			nType = elem.nodeType;

		// don't get/set properties on text, comment and attribute nodes
		if ( !elem || nType === 3 || nType === 8 || nType === 2 ) {
			return;
		}

		notxml = nType !== 1 || !jQuery.isXMLDoc( elem );

		if ( notxml ) {
			// Fix name and attach hooks
			name = jQuery.propFix[ name ] || name;
			hooks = jQuery.propHooks[ name ];
		}

		if ( value !== undefined ) {
			return hooks && "set" in hooks && (ret = hooks.set( elem, value, name )) !== undefined ?
				ret :
				( elem[ name ] = value );

		} else {
			return hooks && "get" in hooks && (ret = hooks.get( elem, name )) !== null ?
				ret :
				elem[ name ];
		}
	},

	propHooks: {
		tabIndex: {
			get: function( elem ) {
				// elem.tabIndex doesn't always return the correct value when it hasn't been explicitly set
				// http://fluidproject.org/blog/2008/01/09/getting-setting-and-removing-tabindex-values-with-javascript/
				// Use proper attribute retrieval(#12072)
				var tabindex = jQuery.find.attr( elem, "tabindex" );

				return tabindex ?
					parseInt( tabindex, 10 ) :
					rfocusable.test( elem.nodeName ) || rclickable.test( elem.nodeName ) && elem.href ?
						0 :
						-1;
			}
		}
	}
});

// Some attributes require a special call on IE
// http://msdn.microsoft.com/en-us/library/ms536429%28VS.85%29.aspx
if ( !support.hrefNormalized ) {
	// href/src property should get the full normalized URL (#10299/#12915)
	jQuery.each([ "href", "src" ], function( i, name ) {
		jQuery.propHooks[ name ] = {
			get: function( elem ) {
				return elem.getAttribute( name, 4 );
			}
		};
	});
}

// Support: Safari, IE9+
// mis-reports the default selected property of an option
// Accessing the parent's selectedIndex property fixes it
if ( !support.optSelected ) {
	jQuery.propHooks.selected = {
		get: function( elem ) {
			var parent = elem.parentNode;

			if ( parent ) {
				parent.selectedIndex;

				// Make sure that it also works with optgroups, see #5701
				if ( parent.parentNode ) {
					parent.parentNode.selectedIndex;
				}
			}
			return null;
		}
	};
}

jQuery.each([
	"tabIndex",
	"readOnly",
	"maxLength",
	"cellSpacing",
	"cellPadding",
	"rowSpan",
	"colSpan",
	"useMap",
	"frameBorder",
	"contentEditable"
], function() {
	jQuery.propFix[ this.toLowerCase() ] = this;
});

// IE6/7 call enctype encoding
if ( !support.enctype ) {
	jQuery.propFix.enctype = "encoding";
}




var rclass = /[\t\r\n\f]/g;

jQuery.fn.extend({
	addClass: function( value ) {
		var classes, elem, cur, clazz, j, finalValue,
			i = 0,
			len = this.length,
			proceed = typeof value === "string" && value;

		if ( jQuery.isFunction( value ) ) {
			return this.each(function( j ) {
				jQuery( this ).addClass( value.call( this, j, this.className ) );
			});
		}

		if ( proceed ) {
			// The disjunction here is for better compressibility (see removeClass)
			classes = ( value || "" ).match( rnotwhite ) || [];

			for ( ; i < len; i++ ) {
				elem = this[ i ];
				cur = elem.nodeType === 1 && ( elem.className ?
					( " " + elem.className + " " ).replace( rclass, " " ) :
					" "
				);

				if ( cur ) {
					j = 0;
					while ( (clazz = classes[j++]) ) {
						if ( cur.indexOf( " " + clazz + " " ) < 0 ) {
							cur += clazz + " ";
						}
					}

					// only assign if different to avoid unneeded rendering.
					finalValue = jQuery.trim( cur );
					if ( elem.className !== finalValue ) {
						elem.className = finalValue;
					}
				}
			}
		}

		return this;
	},

	removeClass: function( value ) {
		var classes, elem, cur, clazz, j, finalValue,
			i = 0,
			len = this.length,
			proceed = arguments.length === 0 || typeof value === "string" && value;

		if ( jQuery.isFunction( value ) ) {
			return this.each(function( j ) {
				jQuery( this ).removeClass( value.call( this, j, this.className ) );
			});
		}
		if ( proceed ) {
			classes = ( value || "" ).match( rnotwhite ) || [];

			for ( ; i < len; i++ ) {
				elem = this[ i ];
				// This expression is here for better compressibility (see addClass)
				cur = elem.nodeType === 1 && ( elem.className ?
					( " " + elem.className + " " ).replace( rclass, " " ) :
					""
				);

				if ( cur ) {
					j = 0;
					while ( (clazz = classes[j++]) ) {
						// Remove *all* instances
						while ( cur.indexOf( " " + clazz + " " ) >= 0 ) {
							cur = cur.replace( " " + clazz + " ", " " );
						}
					}

					// only assign if different to avoid unneeded rendering.
					finalValue = value ? jQuery.trim( cur ) : "";
					if ( elem.className !== finalValue ) {
						elem.className = finalValue;
					}
				}
			}
		}

		return this;
	},

	toggleClass: function( value, stateVal ) {
		var type = typeof value;

		if ( typeof stateVal === "boolean" && type === "string" ) {
			return stateVal ? this.addClass( value ) : this.removeClass( value );
		}

		if ( jQuery.isFunction( value ) ) {
			return this.each(function( i ) {
				jQuery( this ).toggleClass( value.call(this, i, this.className, stateVal), stateVal );
			});
		}

		return this.each(function() {
			if ( type === "string" ) {
				// toggle individual class names
				var className,
					i = 0,
					self = jQuery( this ),
					classNames = value.match( rnotwhite ) || [];

				while ( (className = classNames[ i++ ]) ) {
					// check each className given, space separated list
					if ( self.hasClass( className ) ) {
						self.removeClass( className );
					} else {
						self.addClass( className );
					}
				}

			// Toggle whole class name
			} else if ( type === strundefined || type === "boolean" ) {
				if ( this.className ) {
					// store className if set
					jQuery._data( this, "__className__", this.className );
				}

				// If the element has a class name or if we're passed "false",
				// then remove the whole classname (if there was one, the above saved it).
				// Otherwise bring back whatever was previously saved (if anything),
				// falling back to the empty string if nothing was stored.
				this.className = this.className || value === false ? "" : jQuery._data( this, "__className__" ) || "";
			}
		});
	},

	hasClass: function( selector ) {
		var className = " " + selector + " ",
			i = 0,
			l = this.length;
		for ( ; i < l; i++ ) {
			if ( this[i].nodeType === 1 && (" " + this[i].className + " ").replace(rclass, " ").indexOf( className ) >= 0 ) {
				return true;
			}
		}

		return false;
	}
});




// Return jQuery for attributes-only inclusion


jQuery.each( ("blur focus focusin focusout load resize scroll unload click dblclick " +
	"mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave " +
	"change select submit keydown keypress keyup error contextmenu").split(" "), function( i, name ) {

	// Handle event binding
	jQuery.fn[ name ] = function( data, fn ) {
		return arguments.length > 0 ?
			this.on( name, null, data, fn ) :
			this.trigger( name );
	};
});

jQuery.fn.extend({
	hover: function( fnOver, fnOut ) {
		return this.mouseenter( fnOver ).mouseleave( fnOut || fnOver );
	},

	bind: function( types, data, fn ) {
		return this.on( types, null, data, fn );
	},
	unbind: function( types, fn ) {
		return this.off( types, null, fn );
	},

	delegate: function( selector, types, data, fn ) {
		return this.on( types, selector, data, fn );
	},
	undelegate: function( selector, types, fn ) {
		// ( namespace ) or ( selector, types [, fn] )
		return arguments.length === 1 ? this.off( selector, "**" ) : this.off( types, selector || "**", fn );
	}
});


var nonce = jQuery.now();

var rquery = (/\?/);



var rvalidtokens = /(,)|(\[|{)|(}|])|"(?:[^"\\\r\n]|\\["\\\/bfnrt]|\\u[\da-fA-F]{4})*"\s*:?|true|false|null|-?(?!0\d)\d+(?:\.\d+|)(?:[eE][+-]?\d+|)/g;

jQuery.parseJSON = function( data ) {
	// Attempt to parse using the native JSON parser first
	if ( window.JSON && window.JSON.parse ) {
		// Support: Android 2.3
		// Workaround failure to string-cast null input
		return window.JSON.parse( data + "" );
	}

	var requireNonComma,
		depth = null,
		str = jQuery.trim( data + "" );

	// Guard against invalid (and possibly dangerous) input by ensuring that nothing remains
	// after removing valid tokens
	return str && !jQuery.trim( str.replace( rvalidtokens, function( token, comma, open, close ) {

		// Force termination if we see a misplaced comma
		if ( requireNonComma && comma ) {
			depth = 0;
		}

		// Perform no more replacements after returning to outermost depth
		if ( depth === 0 ) {
			return token;
		}

		// Commas must not follow "[", "{", or ","
		requireNonComma = open || comma;

		// Determine new depth
		// array/object open ("[" or "{"): depth += true - false (increment)
		// array/object close ("]" or "}"): depth += false - true (decrement)
		// other cases ("," or primitive): depth += true - true (numeric cast)
		depth += !close - !open;

		// Remove this token
		return "";
	}) ) ?
		( Function( "return " + str ) )() :
		jQuery.error( "Invalid JSON: " + data );
};


// Cross-browser xml parsing
jQuery.parseXML = function( data ) {
	var xml, tmp;
	if ( !data || typeof data !== "string" ) {
		return null;
	}
	try {
		if ( window.DOMParser ) { // Standard
			tmp = new DOMParser();
			xml = tmp.parseFromString( data, "text/xml" );
		} else { // IE
			xml = new ActiveXObject( "Microsoft.XMLDOM" );
			xml.async = "false";
			xml.loadXML( data );
		}
	} catch( e ) {
		xml = undefined;
	}
	if ( !xml || !xml.documentElement || xml.getElementsByTagName( "parsererror" ).length ) {
		jQuery.error( "Invalid XML: " + data );
	}
	return xml;
};


var
	// Document location
	ajaxLocParts,
	ajaxLocation,

	rhash = /#.*$/,
	rts = /([?&])_=[^&]*/,
	rheaders = /^(.*?):[ \t]*([^\r\n]*)\r?$/mg, // IE leaves an \r character at EOL
	// #7653, #8125, #8152: local protocol detection
	rlocalProtocol = /^(?:about|app|app-storage|.+-extension|file|res|widget):$/,
	rnoContent = /^(?:GET|HEAD)$/,
	rprotocol = /^\/\//,
	rurl = /^([\w.+-]+:)(?:\/\/(?:[^\/?#]*@|)([^\/?#:]*)(?::(\d+)|)|)/,

	/* Prefilters
	 * 1) They are useful to introduce custom dataTypes (see ajax/jsonp.js for an example)
	 * 2) These are called:
	 *    - BEFORE asking for a transport
	 *    - AFTER param serialization (s.data is a string if s.processData is true)
	 * 3) key is the dataType
	 * 4) the catchall symbol "*" can be used
	 * 5) execution will start with transport dataType and THEN continue down to "*" if needed
	 */
	prefilters = {},

	/* Transports bindings
	 * 1) key is the dataType
	 * 2) the catchall symbol "*" can be used
	 * 3) selection will start with transport dataType and THEN go to "*" if needed
	 */
	transports = {},

	// Avoid comment-prolog char sequence (#10098); must appease lint and evade compression
	allTypes = "*/".concat("*");

// #8138, IE may throw an exception when accessing
// a field from window.location if document.domain has been set
try {
	ajaxLocation = location.href;
} catch( e ) {
	// Use the href attribute of an A element
	// since IE will modify it given document.location
	ajaxLocation = document.createElement( "a" );
	ajaxLocation.href = "";
	ajaxLocation = ajaxLocation.href;
}

// Segment location into parts
ajaxLocParts = rurl.exec( ajaxLocation.toLowerCase() ) || [];

// Base "constructor" for jQuery.ajaxPrefilter and jQuery.ajaxTransport
function addToPrefiltersOrTransports( structure ) {

	// dataTypeExpression is optional and defaults to "*"
	return function( dataTypeExpression, func ) {

		if ( typeof dataTypeExpression !== "string" ) {
			func = dataTypeExpression;
			dataTypeExpression = "*";
		}

		var dataType,
			i = 0,
			dataTypes = dataTypeExpression.toLowerCase().match( rnotwhite ) || [];

		if ( jQuery.isFunction( func ) ) {
			// For each dataType in the dataTypeExpression
			while ( (dataType = dataTypes[i++]) ) {
				// Prepend if requested
				if ( dataType.charAt( 0 ) === "+" ) {
					dataType = dataType.slice( 1 ) || "*";
					(structure[ dataType ] = structure[ dataType ] || []).unshift( func );

				// Otherwise append
				} else {
					(structure[ dataType ] = structure[ dataType ] || []).push( func );
				}
			}
		}
	};
}

// Base inspection function for prefilters and transports
function inspectPrefiltersOrTransports( structure, options, originalOptions, jqXHR ) {

	var inspected = {},
		seekingTransport = ( structure === transports );

	function inspect( dataType ) {
		var selected;
		inspected[ dataType ] = true;
		jQuery.each( structure[ dataType ] || [], function( _, prefilterOrFactory ) {
			var dataTypeOrTransport = prefilterOrFactory( options, originalOptions, jqXHR );
			if ( typeof dataTypeOrTransport === "string" && !seekingTransport && !inspected[ dataTypeOrTransport ] ) {
				options.dataTypes.unshift( dataTypeOrTransport );
				inspect( dataTypeOrTransport );
				return false;
			} else if ( seekingTransport ) {
				return !( selected = dataTypeOrTransport );
			}
		});
		return selected;
	}

	return inspect( options.dataTypes[ 0 ] ) || !inspected[ "*" ] && inspect( "*" );
}

// A special extend for ajax options
// that takes "flat" options (not to be deep extended)
// Fixes #9887
function ajaxExtend( target, src ) {
	var deep, key,
		flatOptions = jQuery.ajaxSettings.flatOptions || {};

	for ( key in src ) {
		if ( src[ key ] !== undefined ) {
			( flatOptions[ key ] ? target : ( deep || (deep = {}) ) )[ key ] = src[ key ];
		}
	}
	if ( deep ) {
		jQuery.extend( true, target, deep );
	}

	return target;
}

/* Handles responses to an ajax request:
 * - finds the right dataType (mediates between content-type and expected dataType)
 * - returns the corresponding response
 */
function ajaxHandleResponses( s, jqXHR, responses ) {
	var firstDataType, ct, finalDataType, type,
		contents = s.contents,
		dataTypes = s.dataTypes;

	// Remove auto dataType and get content-type in the process
	while ( dataTypes[ 0 ] === "*" ) {
		dataTypes.shift();
		if ( ct === undefined ) {
			ct = s.mimeType || jqXHR.getResponseHeader("Content-Type");
		}
	}

	// Check if we're dealing with a known content-type
	if ( ct ) {
		for ( type in contents ) {
			if ( contents[ type ] && contents[ type ].test( ct ) ) {
				dataTypes.unshift( type );
				break;
			}
		}
	}

	// Check to see if we have a response for the expected dataType
	if ( dataTypes[ 0 ] in responses ) {
		finalDataType = dataTypes[ 0 ];
	} else {
		// Try convertible dataTypes
		for ( type in responses ) {
			if ( !dataTypes[ 0 ] || s.converters[ type + " " + dataTypes[0] ] ) {
				finalDataType = type;
				break;
			}
			if ( !firstDataType ) {
				firstDataType = type;
			}
		}
		// Or just use first one
		finalDataType = finalDataType || firstDataType;
	}

	// If we found a dataType
	// We add the dataType to the list if needed
	// and return the corresponding response
	if ( finalDataType ) {
		if ( finalDataType !== dataTypes[ 0 ] ) {
			dataTypes.unshift( finalDataType );
		}
		return responses[ finalDataType ];
	}
}

/* Chain conversions given the request and the original response
 * Also sets the responseXXX fields on the jqXHR instance
 */
function ajaxConvert( s, response, jqXHR, isSuccess ) {
	var conv2, current, conv, tmp, prev,
		converters = {},
		// Work with a copy of dataTypes in case we need to modify it for conversion
		dataTypes = s.dataTypes.slice();

	// Create converters map with lowercased keys
	if ( dataTypes[ 1 ] ) {
		for ( conv in s.converters ) {
			converters[ conv.toLowerCase() ] = s.converters[ conv ];
		}
	}

	current = dataTypes.shift();

	// Convert to each sequential dataType
	while ( current ) {

		if ( s.responseFields[ current ] ) {
			jqXHR[ s.responseFields[ current ] ] = response;
		}

		// Apply the dataFilter if provided
		if ( !prev && isSuccess && s.dataFilter ) {
			response = s.dataFilter( response, s.dataType );
		}

		prev = current;
		current = dataTypes.shift();

		if ( current ) {

			// There's only work to do if current dataType is non-auto
			if ( current === "*" ) {

				current = prev;

			// Convert response if prev dataType is non-auto and differs from current
			} else if ( prev !== "*" && prev !== current ) {

				// Seek a direct converter
				conv = converters[ prev + " " + current ] || converters[ "* " + current ];

				// If none found, seek a pair
				if ( !conv ) {
					for ( conv2 in converters ) {

						// If conv2 outputs current
						tmp = conv2.split( " " );
						if ( tmp[ 1 ] === current ) {

							// If prev can be converted to accepted input
							conv = converters[ prev + " " + tmp[ 0 ] ] ||
								converters[ "* " + tmp[ 0 ] ];
							if ( conv ) {
								// Condense equivalence converters
								if ( conv === true ) {
									conv = converters[ conv2 ];

								// Otherwise, insert the intermediate dataType
								} else if ( converters[ conv2 ] !== true ) {
									current = tmp[ 0 ];
									dataTypes.unshift( tmp[ 1 ] );
								}
								break;
							}
						}
					}
				}

				// Apply converter (if not an equivalence)
				if ( conv !== true ) {

					// Unless errors are allowed to bubble, catch and return them
					if ( conv && s[ "throws" ] ) {
						response = conv( response );
					} else {
						try {
							response = conv( response );
						} catch ( e ) {
							return { state: "parsererror", error: conv ? e : "No conversion from " + prev + " to " + current };
						}
					}
				}
			}
		}
	}

	return { state: "success", data: response };
}

jQuery.extend({

	// Counter for holding the number of active queries
	active: 0,

	// Last-Modified header cache for next request
	lastModified: {},
	etag: {},

	ajaxSettings: {
		url: ajaxLocation,
		type: "GET",
		isLocal: rlocalProtocol.test( ajaxLocParts[ 1 ] ),
		global: true,
		processData: true,
		async: true,
		contentType: "application/x-www-form-urlencoded; charset=UTF-8",
		/*
		timeout: 0,
		data: null,
		dataType: null,
		username: null,
		password: null,
		cache: null,
		throws: false,
		traditional: false,
		headers: {},
		*/

		accepts: {
			"*": allTypes,
			text: "text/plain",
			html: "text/html",
			xml: "application/xml, text/xml",
			json: "application/json, text/javascript"
		},

		contents: {
			xml: /xml/,
			html: /html/,
			json: /json/
		},

		responseFields: {
			xml: "responseXML",
			text: "responseText",
			json: "responseJSON"
		},

		// Data converters
		// Keys separate source (or catchall "*") and destination types with a single space
		converters: {

			// Convert anything to text
			"* text": String,

			// Text to html (true = no transformation)
			"text html": true,

			// Evaluate text as a json expression
			"text json": jQuery.parseJSON,

			// Parse text as xml
			"text xml": jQuery.parseXML
		},

		// For options that shouldn't be deep extended:
		// you can add your own custom options here if
		// and when you create one that shouldn't be
		// deep extended (see ajaxExtend)
		flatOptions: {
			url: true,
			context: true
		}
	},

	// Creates a full fledged settings object into target
	// with both ajaxSettings and settings fields.
	// If target is omitted, writes into ajaxSettings.
	ajaxSetup: function( target, settings ) {
		return settings ?

			// Building a settings object
			ajaxExtend( ajaxExtend( target, jQuery.ajaxSettings ), settings ) :

			// Extending ajaxSettings
			ajaxExtend( jQuery.ajaxSettings, target );
	},

	ajaxPrefilter: addToPrefiltersOrTransports( prefilters ),
	ajaxTransport: addToPrefiltersOrTransports( transports ),

	// Main method
	ajax: function( url, options ) {

		// If url is an object, simulate pre-1.5 signature
		if ( typeof url === "object" ) {
			options = url;
			url = undefined;
		}

		// Force options to be an object
		options = options || {};

		var // Cross-domain detection vars
			parts,
			// Loop variable
			i,
			// URL without anti-cache param
			cacheURL,
			// Response headers as string
			responseHeadersString,
			// timeout handle
			timeoutTimer,

			// To know if global events are to be dispatched
			fireGlobals,

			transport,
			// Response headers
			responseHeaders,
			// Create the final options object
			s = jQuery.ajaxSetup( {}, options ),
			// Callbacks context
			callbackContext = s.context || s,
			// Context for global events is callbackContext if it is a DOM node or jQuery collection
			globalEventContext = s.context && ( callbackContext.nodeType || callbackContext.jquery ) ?
				jQuery( callbackContext ) :
				jQuery.event,
			// Deferreds
			deferred = jQuery.Deferred(),
			completeDeferred = jQuery.Callbacks("once memory"),
			// Status-dependent callbacks
			statusCode = s.statusCode || {},
			// Headers (they are sent all at once)
			requestHeaders = {},
			requestHeadersNames = {},
			// The jqXHR state
			state = 0,
			// Default abort message
			strAbort = "canceled",
			// Fake xhr
			jqXHR = {
				readyState: 0,

				// Builds headers hashtable if needed
				getResponseHeader: function( key ) {
					var match;
					if ( state === 2 ) {
						if ( !responseHeaders ) {
							responseHeaders = {};
							while ( (match = rheaders.exec( responseHeadersString )) ) {
								responseHeaders[ match[1].toLowerCase() ] = match[ 2 ];
							}
						}
						match = responseHeaders[ key.toLowerCase() ];
					}
					return match == null ? null : match;
				},

				// Raw string
				getAllResponseHeaders: function() {
					return state === 2 ? responseHeadersString : null;
				},

				// Caches the header
				setRequestHeader: function( name, value ) {
					var lname = name.toLowerCase();
					if ( !state ) {
						name = requestHeadersNames[ lname ] = requestHeadersNames[ lname ] || name;
						requestHeaders[ name ] = value;
					}
					return this;
				},

				// Overrides response content-type header
				overrideMimeType: function( type ) {
					if ( !state ) {
						s.mimeType = type;
					}
					return this;
				},

				// Status-dependent callbacks
				statusCode: function( map ) {
					var code;
					if ( map ) {
						if ( state < 2 ) {
							for ( code in map ) {
								// Lazy-add the new callback in a way that preserves old ones
								statusCode[ code ] = [ statusCode[ code ], map[ code ] ];
							}
						} else {
							// Execute the appropriate callbacks
							jqXHR.always( map[ jqXHR.status ] );
						}
					}
					return this;
				},

				// Cancel the request
				abort: function( statusText ) {
					var finalText = statusText || strAbort;
					if ( transport ) {
						transport.abort( finalText );
					}
					done( 0, finalText );
					return this;
				}
			};

		// Attach deferreds
		deferred.promise( jqXHR ).complete = completeDeferred.add;
		jqXHR.success = jqXHR.done;
		jqXHR.error = jqXHR.fail;

		// Remove hash character (#7531: and string promotion)
		// Add protocol if not provided (#5866: IE7 issue with protocol-less urls)
		// Handle falsy url in the settings object (#10093: consistency with old signature)
		// We also use the url parameter if available
		s.url = ( ( url || s.url || ajaxLocation ) + "" ).replace( rhash, "" ).replace( rprotocol, ajaxLocParts[ 1 ] + "//" );

		// Alias method option to type as per ticket #12004
		s.type = options.method || options.type || s.method || s.type;

		// Extract dataTypes list
		s.dataTypes = jQuery.trim( s.dataType || "*" ).toLowerCase().match( rnotwhite ) || [ "" ];

		// A cross-domain request is in order when we have a protocol:host:port mismatch
		if ( s.crossDomain == null ) {
			parts = rurl.exec( s.url.toLowerCase() );
			s.crossDomain = !!( parts &&
				( parts[ 1 ] !== ajaxLocParts[ 1 ] || parts[ 2 ] !== ajaxLocParts[ 2 ] ||
					( parts[ 3 ] || ( parts[ 1 ] === "http:" ? "80" : "443" ) ) !==
						( ajaxLocParts[ 3 ] || ( ajaxLocParts[ 1 ] === "http:" ? "80" : "443" ) ) )
			);
		}

		// Convert data if not already a string
		if ( s.data && s.processData && typeof s.data !== "string" ) {
			s.data = jQuery.param( s.data, s.traditional );
		}

		// Apply prefilters
		inspectPrefiltersOrTransports( prefilters, s, options, jqXHR );

		// If request was aborted inside a prefilter, stop there
		if ( state === 2 ) {
			return jqXHR;
		}

		// We can fire global events as of now if asked to
		// Don't fire events if jQuery.event is undefined in an AMD-usage scenario (#15118)
		fireGlobals = jQuery.event && s.global;

		// Watch for a new set of requests
		if ( fireGlobals && jQuery.active++ === 0 ) {
			jQuery.event.trigger("ajaxStart");
		}

		// Uppercase the type
		s.type = s.type.toUpperCase();

		// Determine if request has content
		s.hasContent = !rnoContent.test( s.type );

		// Save the URL in case we're toying with the If-Modified-Since
		// and/or If-None-Match header later on
		cacheURL = s.url;

		// More options handling for requests with no content
		if ( !s.hasContent ) {

			// If data is available, append data to url
			if ( s.data ) {
				cacheURL = ( s.url += ( rquery.test( cacheURL ) ? "&" : "?" ) + s.data );
				// #9682: remove data so that it's not used in an eventual retry
				delete s.data;
			}

			// Add anti-cache in url if needed
			if ( s.cache === false ) {
				s.url = rts.test( cacheURL ) ?

					// If there is already a '_' parameter, set its value
					cacheURL.replace( rts, "$1_=" + nonce++ ) :

					// Otherwise add one to the end
					cacheURL + ( rquery.test( cacheURL ) ? "&" : "?" ) + "_=" + nonce++;
			}
		}

		// Set the If-Modified-Since and/or If-None-Match header, if in ifModified mode.
		if ( s.ifModified ) {
			if ( jQuery.lastModified[ cacheURL ] ) {
				jqXHR.setRequestHeader( "If-Modified-Since", jQuery.lastModified[ cacheURL ] );
			}
			if ( jQuery.etag[ cacheURL ] ) {
				jqXHR.setRequestHeader( "If-None-Match", jQuery.etag[ cacheURL ] );
			}
		}

		// Set the correct header, if data is being sent
		if ( s.data && s.hasContent && s.contentType !== false || options.contentType ) {
			jqXHR.setRequestHeader( "Content-Type", s.contentType );
		}

		// Set the Accepts header for the server, depending on the dataType
		jqXHR.setRequestHeader(
			"Accept",
			s.dataTypes[ 0 ] && s.accepts[ s.dataTypes[0] ] ?
				s.accepts[ s.dataTypes[0] ] + ( s.dataTypes[ 0 ] !== "*" ? ", " + allTypes + "; q=0.01" : "" ) :
				s.accepts[ "*" ]
		);

		// Check for headers option
		for ( i in s.headers ) {
			jqXHR.setRequestHeader( i, s.headers[ i ] );
		}

		// Allow custom headers/mimetypes and early abort
		if ( s.beforeSend && ( s.beforeSend.call( callbackContext, jqXHR, s ) === false || state === 2 ) ) {
			// Abort if not done already and return
			return jqXHR.abort();
		}

		// aborting is no longer a cancellation
		strAbort = "abort";

		// Install callbacks on deferreds
		for ( i in { success: 1, error: 1, complete: 1 } ) {
			jqXHR[ i ]( s[ i ] );
		}

		// Get transport
		transport = inspectPrefiltersOrTransports( transports, s, options, jqXHR );

		// If no transport, we auto-abort
		if ( !transport ) {
			done( -1, "No Transport" );
		} else {
			jqXHR.readyState = 1;

			// Send global event
			if ( fireGlobals ) {
				globalEventContext.trigger( "ajaxSend", [ jqXHR, s ] );
			}
			// Timeout
			if ( s.async && s.timeout > 0 ) {
				timeoutTimer = setTimeout(function() {
					jqXHR.abort("timeout");
				}, s.timeout );
			}

			try {
				state = 1;
				transport.send( requestHeaders, done );
			} catch ( e ) {
				// Propagate exception as error if not done
				if ( state < 2 ) {
					done( -1, e );
				// Simply rethrow otherwise
				} else {
					throw e;
				}
			}
		}

		// Callback for when everything is done
		function done( status, nativeStatusText, responses, headers ) {
			var isSuccess, success, error, response, modified,
				statusText = nativeStatusText;

			// Called once
			if ( state === 2 ) {
				return;
			}

			// State is "done" now
			state = 2;

			// Clear timeout if it exists
			if ( timeoutTimer ) {
				clearTimeout( timeoutTimer );
			}

			// Dereference transport for early garbage collection
			// (no matter how long the jqXHR object will be used)
			transport = undefined;

			// Cache response headers
			responseHeadersString = headers || "";

			// Set readyState
			jqXHR.readyState = status > 0 ? 4 : 0;

			// Determine if successful
			isSuccess = status >= 200 && status < 300 || status === 304;

			// Get response data
			if ( responses ) {
				response = ajaxHandleResponses( s, jqXHR, responses );
			}

			// Convert no matter what (that way responseXXX fields are always set)
			response = ajaxConvert( s, response, jqXHR, isSuccess );

			// If successful, handle type chaining
			if ( isSuccess ) {

				// Set the If-Modified-Since and/or If-None-Match header, if in ifModified mode.
				if ( s.ifModified ) {
					modified = jqXHR.getResponseHeader("Last-Modified");
					if ( modified ) {
						jQuery.lastModified[ cacheURL ] = modified;
					}
					modified = jqXHR.getResponseHeader("etag");
					if ( modified ) {
						jQuery.etag[ cacheURL ] = modified;
					}
				}

				// if no content
				if ( status === 204 || s.type === "HEAD" ) {
					statusText = "nocontent";

				// if not modified
				} else if ( status === 304 ) {
					statusText = "notmodified";

				// If we have data, let's convert it
				} else {
					statusText = response.state;
					success = response.data;
					error = response.error;
					isSuccess = !error;
				}
			} else {
				// We extract error from statusText
				// then normalize statusText and status for non-aborts
				error = statusText;
				if ( status || !statusText ) {
					statusText = "error";
					if ( status < 0 ) {
						status = 0;
					}
				}
			}

			// Set data for the fake xhr object
			jqXHR.status = status;
			jqXHR.statusText = ( nativeStatusText || statusText ) + "";

			// Success/Error
			if ( isSuccess ) {
				deferred.resolveWith( callbackContext, [ success, statusText, jqXHR ] );
			} else {
				deferred.rejectWith( callbackContext, [ jqXHR, statusText, error ] );
			}

			// Status-dependent callbacks
			jqXHR.statusCode( statusCode );
			statusCode = undefined;

			if ( fireGlobals ) {
				globalEventContext.trigger( isSuccess ? "ajaxSuccess" : "ajaxError",
					[ jqXHR, s, isSuccess ? success : error ] );
			}

			// Complete
			completeDeferred.fireWith( callbackContext, [ jqXHR, statusText ] );

			if ( fireGlobals ) {
				globalEventContext.trigger( "ajaxComplete", [ jqXHR, s ] );
				// Handle the global AJAX counter
				if ( !( --jQuery.active ) ) {
					jQuery.event.trigger("ajaxStop");
				}
			}
		}

		return jqXHR;
	},

	getJSON: function( url, data, callback ) {
		return jQuery.get( url, data, callback, "json" );
	},

	getScript: function( url, callback ) {
		return jQuery.get( url, undefined, callback, "script" );
	}
});

jQuery.each( [ "get", "post" ], function( i, method ) {
	jQuery[ method ] = function( url, data, callback, type ) {
		// shift arguments if data argument was omitted
		if ( jQuery.isFunction( data ) ) {
			type = type || callback;
			callback = data;
			data = undefined;
		}

		return jQuery.ajax({
			url: url,
			type: method,
			dataType: type,
			data: data,
			success: callback
		});
	};
});


jQuery._evalUrl = function( url ) {
	return jQuery.ajax({
		url: url,
		type: "GET",
		dataType: "script",
		async: false,
		global: false,
		"throws": true
	});
};


jQuery.fn.extend({
	wrapAll: function( html ) {
		if ( jQuery.isFunction( html ) ) {
			return this.each(function(i) {
				jQuery(this).wrapAll( html.call(this, i) );
			});
		}

		if ( this[0] ) {
			// The elements to wrap the target around
			var wrap = jQuery( html, this[0].ownerDocument ).eq(0).clone(true);

			if ( this[0].parentNode ) {
				wrap.insertBefore( this[0] );
			}

			wrap.map(function() {
				var elem = this;

				while ( elem.firstChild && elem.firstChild.nodeType === 1 ) {
					elem = elem.firstChild;
				}

				return elem;
			}).append( this );
		}

		return this;
	},

	wrapInner: function( html ) {
		if ( jQuery.isFunction( html ) ) {
			return this.each(function(i) {
				jQuery(this).wrapInner( html.call(this, i) );
			});
		}

		return this.each(function() {
			var self = jQuery( this ),
				contents = self.contents();

			if ( contents.length ) {
				contents.wrapAll( html );

			} else {
				self.append( html );
			}
		});
	},

	wrap: function( html ) {
		var isFunction = jQuery.isFunction( html );

		return this.each(function(i) {
			jQuery( this ).wrapAll( isFunction ? html.call(this, i) : html );
		});
	},

	unwrap: function() {
		return this.parent().each(function() {
			if ( !jQuery.nodeName( this, "body" ) ) {
				jQuery( this ).replaceWith( this.childNodes );
			}
		}).end();
	}
});


jQuery.expr.filters.hidden = function( elem ) {
	// Support: Opera <= 12.12
	// Opera reports offsetWidths and offsetHeights less than zero on some elements
	return elem.offsetWidth <= 0 && elem.offsetHeight <= 0 ||
		(!support.reliableHiddenOffsets() &&
			((elem.style && elem.style.display) || jQuery.css( elem, "display" )) === "none");
};

jQuery.expr.filters.visible = function( elem ) {
	return !jQuery.expr.filters.hidden( elem );
};




var r20 = /%20/g,
	rbracket = /\[\]$/,
	rCRLF = /\r?\n/g,
	rsubmitterTypes = /^(?:submit|button|image|reset|file)$/i,
	rsubmittable = /^(?:input|select|textarea|keygen)/i;

function buildParams( prefix, obj, traditional, add ) {
	var name;

	if ( jQuery.isArray( obj ) ) {
		// Serialize array item.
		jQuery.each( obj, function( i, v ) {
			if ( traditional || rbracket.test( prefix ) ) {
				// Treat each array item as a scalar.
				add( prefix, v );

			} else {
				// Item is non-scalar (array or object), encode its numeric index.
				buildParams( prefix + "[" + ( typeof v === "object" ? i : "" ) + "]", v, traditional, add );
			}
		});

	} else if ( !traditional && jQuery.type( obj ) === "object" ) {
		// Serialize object item.
		for ( name in obj ) {
			buildParams( prefix + "[" + name + "]", obj[ name ], traditional, add );
		}

	} else {
		// Serialize scalar item.
		add( prefix, obj );
	}
}

// Serialize an array of form elements or a set of
// key/values into a query string
jQuery.param = function( a, traditional ) {
	var prefix,
		s = [],
		add = function( key, value ) {
			// If value is a function, invoke it and return its value
			value = jQuery.isFunction( value ) ? value() : ( value == null ? "" : value );
			s[ s.length ] = encodeURIComponent( key ) + "=" + encodeURIComponent( value );
		};

	// Set traditional to true for jQuery <= 1.3.2 behavior.
	if ( traditional === undefined ) {
		traditional = jQuery.ajaxSettings && jQuery.ajaxSettings.traditional;
	}

	// If an array was passed in, assume that it is an array of form elements.
	if ( jQuery.isArray( a ) || ( a.jquery && !jQuery.isPlainObject( a ) ) ) {
		// Serialize the form elements
		jQuery.each( a, function() {
			add( this.name, this.value );
		});

	} else {
		// If traditional, encode the "old" way (the way 1.3.2 or older
		// did it), otherwise encode params recursively.
		for ( prefix in a ) {
			buildParams( prefix, a[ prefix ], traditional, add );
		}
	}

	// Return the resulting serialization
	return s.join( "&" ).replace( r20, "+" );
};

jQuery.fn.extend({
	serialize: function() {
		return jQuery.param( this.serializeArray() );
	},
	serializeArray: function() {
		return this.map(function() {
			// Can add propHook for "elements" to filter or add form elements
			var elements = jQuery.prop( this, "elements" );
			return elements ? jQuery.makeArray( elements ) : this;
		})
		.filter(function() {
			var type = this.type;
			// Use .is(":disabled") so that fieldset[disabled] works
			return this.name && !jQuery( this ).is( ":disabled" ) &&
				rsubmittable.test( this.nodeName ) && !rsubmitterTypes.test( type ) &&
				( this.checked || !rcheckableType.test( type ) );
		})
		.map(function( i, elem ) {
			var val = jQuery( this ).val();

			return val == null ?
				null :
				jQuery.isArray( val ) ?
					jQuery.map( val, function( val ) {
						return { name: elem.name, value: val.replace( rCRLF, "\r\n" ) };
					}) :
					{ name: elem.name, value: val.replace( rCRLF, "\r\n" ) };
		}).get();
	}
});


// Create the request object
// (This is still attached to ajaxSettings for backward compatibility)
jQuery.ajaxSettings.xhr = window.ActiveXObject !== undefined ?
	// Support: IE6+
	function() {

		// XHR cannot access local files, always use ActiveX for that case
		return !this.isLocal &&

			// Support: IE7-8
			// oldIE XHR does not support non-RFC2616 methods (#13240)
			// See http://msdn.microsoft.com/en-us/library/ie/ms536648(v=vs.85).aspx
			// and http://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9
			// Although this check for six methods instead of eight
			// since IE also does not support "trace" and "connect"
			/^(get|post|head|put|delete|options)$/i.test( this.type ) &&

			createStandardXHR() || createActiveXHR();
	} :
	// For all other browsers, use the standard XMLHttpRequest object
	createStandardXHR;

var xhrId = 0,
	xhrCallbacks = {},
	xhrSupported = jQuery.ajaxSettings.xhr();

// Support: IE<10
// Open requests must be manually aborted on unload (#5280)
// See https://support.microsoft.com/kb/2856746 for more info
if ( window.attachEvent ) {
	window.attachEvent( "onunload", function() {
		for ( var key in xhrCallbacks ) {
			xhrCallbacks[ key ]( undefined, true );
		}
	});
}

// Determine support properties
support.cors = !!xhrSupported && ( "withCredentials" in xhrSupported );
xhrSupported = support.ajax = !!xhrSupported;

// Create transport if the browser can provide an xhr
if ( xhrSupported ) {

	jQuery.ajaxTransport(function( options ) {
		// Cross domain only allowed if supported through XMLHttpRequest
		if ( !options.crossDomain || support.cors ) {

			var callback;

			return {
				send: function( headers, complete ) {
					var i,
						xhr = options.xhr(),
						id = ++xhrId;

					// Open the socket
					xhr.open( options.type, options.url, options.async, options.username, options.password );

					// Apply custom fields if provided
					if ( options.xhrFields ) {
						for ( i in options.xhrFields ) {
							xhr[ i ] = options.xhrFields[ i ];
						}
					}

					// Override mime type if needed
					if ( options.mimeType && xhr.overrideMimeType ) {
						xhr.overrideMimeType( options.mimeType );
					}

					// X-Requested-With header
					// For cross-domain requests, seeing as conditions for a preflight are
					// akin to a jigsaw puzzle, we simply never set it to be sure.
					// (it can always be set on a per-request basis or even using ajaxSetup)
					// For same-domain requests, won't change header if already provided.
					if ( !options.crossDomain && !headers["X-Requested-With"] ) {
						headers["X-Requested-With"] = "XMLHttpRequest";
					}

					// Set headers
					for ( i in headers ) {
						// Support: IE<9
						// IE's ActiveXObject throws a 'Type Mismatch' exception when setting
						// request header to a null-value.
						//
						// To keep consistent with other XHR implementations, cast the value
						// to string and ignore `undefined`.
						if ( headers[ i ] !== undefined ) {
							xhr.setRequestHeader( i, headers[ i ] + "" );
						}
					}

					// Do send the request
					// This may raise an exception which is actually
					// handled in jQuery.ajax (so no try/catch here)
					xhr.send( ( options.hasContent && options.data ) || null );

					// Listener
					callback = function( _, isAbort ) {
						var status, statusText, responses;

						// Was never called and is aborted or complete
						if ( callback && ( isAbort || xhr.readyState === 4 ) ) {
							// Clean up
							delete xhrCallbacks[ id ];
							callback = undefined;
							xhr.onreadystatechange = jQuery.noop;

							// Abort manually if needed
							if ( isAbort ) {
								if ( xhr.readyState !== 4 ) {
									xhr.abort();
								}
							} else {
								responses = {};
								status = xhr.status;

								// Support: IE<10
								// Accessing binary-data responseText throws an exception
								// (#11426)
								if ( typeof xhr.responseText === "string" ) {
									responses.text = xhr.responseText;
								}

								// Firefox throws an exception when accessing
								// statusText for faulty cross-domain requests
								try {
									statusText = xhr.statusText;
								} catch( e ) {
									// We normalize with Webkit giving an empty statusText
									statusText = "";
								}

								// Filter status for non standard behaviors

								// If the request is local and we have data: assume a success
								// (success with no data won't get notified, that's the best we
								// can do given current implementations)
								if ( !status && options.isLocal && !options.crossDomain ) {
									status = responses.text ? 200 : 404;
								// IE - #1450: sometimes returns 1223 when it should be 204
								} else if ( status === 1223 ) {
									status = 204;
								}
							}
						}

						// Call complete if needed
						if ( responses ) {
							complete( status, statusText, responses, xhr.getAllResponseHeaders() );
						}
					};

					if ( !options.async ) {
						// if we're in sync mode we fire the callback
						callback();
					} else if ( xhr.readyState === 4 ) {
						// (IE6 & IE7) if it's in cache and has been
						// retrieved directly we need to fire the callback
						setTimeout( callback );
					} else {
						// Add to the list of active xhr callbacks
						xhr.onreadystatechange = xhrCallbacks[ id ] = callback;
					}
				},

				abort: function() {
					if ( callback ) {
						callback( undefined, true );
					}
				}
			};
		}
	});
}

// Functions to create xhrs
function createStandardXHR() {
	try {
		return new window.XMLHttpRequest();
	} catch( e ) {}
}

function createActiveXHR() {
	try {
		return new window.ActiveXObject( "Microsoft.XMLHTTP" );
	} catch( e ) {}
}




// Install script dataType
jQuery.ajaxSetup({
	accepts: {
		script: "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript"
	},
	contents: {
		script: /(?:java|ecma)script/
	},
	converters: {
		"text script": function( text ) {
			jQuery.globalEval( text );
			return text;
		}
	}
});

// Handle cache's special case and global
jQuery.ajaxPrefilter( "script", function( s ) {
	if ( s.cache === undefined ) {
		s.cache = false;
	}
	if ( s.crossDomain ) {
		s.type = "GET";
		s.global = false;
	}
});

// Bind script tag hack transport
jQuery.ajaxTransport( "script", function(s) {

	// This transport only deals with cross domain requests
	if ( s.crossDomain ) {

		var script,
			head = document.head || jQuery("head")[0] || document.documentElement;

		return {

			send: function( _, callback ) {

				script = document.createElement("script");

				script.async = true;

				if ( s.scriptCharset ) {
					script.charset = s.scriptCharset;
				}

				script.src = s.url;

				// Attach handlers for all browsers
				script.onload = script.onreadystatechange = function( _, isAbort ) {

					if ( isAbort || !script.readyState || /loaded|complete/.test( script.readyState ) ) {

						// Handle memory leak in IE
						script.onload = script.onreadystatechange = null;

						// Remove the script
						if ( script.parentNode ) {
							script.parentNode.removeChild( script );
						}

						// Dereference the script
						script = null;

						// Callback if not abort
						if ( !isAbort ) {
							callback( 200, "success" );
						}
					}
				};

				// Circumvent IE6 bugs with base elements (#2709 and #4378) by prepending
				// Use native DOM manipulation to avoid our domManip AJAX trickery
				head.insertBefore( script, head.firstChild );
			},

			abort: function() {
				if ( script ) {
					script.onload( undefined, true );
				}
			}
		};
	}
});




var oldCallbacks = [],
	rjsonp = /(=)\?(?=&|$)|\?\?/;

// Default jsonp settings
jQuery.ajaxSetup({
	jsonp: "callback",
	jsonpCallback: function() {
		var callback = oldCallbacks.pop() || ( jQuery.expando + "_" + ( nonce++ ) );
		this[ callback ] = true;
		return callback;
	}
});

// Detect, normalize options and install callbacks for jsonp requests
jQuery.ajaxPrefilter( "json jsonp", function( s, originalSettings, jqXHR ) {

	var callbackName, overwritten, responseContainer,
		jsonProp = s.jsonp !== false && ( rjsonp.test( s.url ) ?
			"url" :
			typeof s.data === "string" && !( s.contentType || "" ).indexOf("application/x-www-form-urlencoded") && rjsonp.test( s.data ) && "data"
		);

	// Handle iff the expected data type is "jsonp" or we have a parameter to set
	if ( jsonProp || s.dataTypes[ 0 ] === "jsonp" ) {

		// Get callback name, remembering preexisting value associated with it
		callbackName = s.jsonpCallback = jQuery.isFunction( s.jsonpCallback ) ?
			s.jsonpCallback() :
			s.jsonpCallback;

		// Insert callback into url or form data
		if ( jsonProp ) {
			s[ jsonProp ] = s[ jsonProp ].replace( rjsonp, "$1" + callbackName );
		} else if ( s.jsonp !== false ) {
			s.url += ( rquery.test( s.url ) ? "&" : "?" ) + s.jsonp + "=" + callbackName;
		}

		// Use data converter to retrieve json after script execution
		s.converters["script json"] = function() {
			if ( !responseContainer ) {
				jQuery.error( callbackName + " was not called" );
			}
			return responseContainer[ 0 ];
		};

		// force json dataType
		s.dataTypes[ 0 ] = "json";

		// Install callback
		overwritten = window[ callbackName ];
		window[ callbackName ] = function() {
			responseContainer = arguments;
		};

		// Clean-up function (fires after converters)
		jqXHR.always(function() {
			// Restore preexisting value
			window[ callbackName ] = overwritten;

			// Save back as free
			if ( s[ callbackName ] ) {
				// make sure that re-using the options doesn't screw things around
				s.jsonpCallback = originalSettings.jsonpCallback;

				// save the callback name for future use
				oldCallbacks.push( callbackName );
			}

			// Call if it was a function and we have a response
			if ( responseContainer && jQuery.isFunction( overwritten ) ) {
				overwritten( responseContainer[ 0 ] );
			}

			responseContainer = overwritten = undefined;
		});

		// Delegate to script
		return "script";
	}
});




// data: string of html
// context (optional): If specified, the fragment will be created in this context, defaults to document
// keepScripts (optional): If true, will include scripts passed in the html string
jQuery.parseHTML = function( data, context, keepScripts ) {
	if ( !data || typeof data !== "string" ) {
		return null;
	}
	if ( typeof context === "boolean" ) {
		keepScripts = context;
		context = false;
	}
	context = context || document;

	var parsed = rsingleTag.exec( data ),
		scripts = !keepScripts && [];

	// Single tag
	if ( parsed ) {
		return [ context.createElement( parsed[1] ) ];
	}

	parsed = jQuery.buildFragment( [ data ], context, scripts );

	if ( scripts && scripts.length ) {
		jQuery( scripts ).remove();
	}

	return jQuery.merge( [], parsed.childNodes );
};


// Keep a copy of the old load method
var _load = jQuery.fn.load;

/**
 * Load a url into a page
 */
jQuery.fn.load = function( url, params, callback ) {
	if ( typeof url !== "string" && _load ) {
		return _load.apply( this, arguments );
	}

	var selector, response, type,
		self = this,
		off = url.indexOf(" ");

	if ( off >= 0 ) {
		selector = jQuery.trim( url.slice( off, url.length ) );
		url = url.slice( 0, off );
	}

	// If it's a function
	if ( jQuery.isFunction( params ) ) {

		// We assume that it's the callback
		callback = params;
		params = undefined;

	// Otherwise, build a param string
	} else if ( params && typeof params === "object" ) {
		type = "POST";
	}

	// If we have elements to modify, make the request
	if ( self.length > 0 ) {
		jQuery.ajax({
			url: url,

			// if "type" variable is undefined, then "GET" method will be used
			type: type,
			dataType: "html",
			data: params
		}).done(function( responseText ) {

			// Save response for use in complete callback
			response = arguments;

			self.html( selector ?

				// If a selector was specified, locate the right elements in a dummy div
				// Exclude scripts to avoid IE 'Permission Denied' errors
				jQuery("<div>").append( jQuery.parseHTML( responseText ) ).find( selector ) :

				// Otherwise use the full result
				responseText );

		}).complete( callback && function( jqXHR, status ) {
			self.each( callback, response || [ jqXHR.responseText, status, jqXHR ] );
		});
	}

	return this;
};




// Attach a bunch of functions for handling common AJAX events
jQuery.each( [ "ajaxStart", "ajaxStop", "ajaxComplete", "ajaxError", "ajaxSuccess", "ajaxSend" ], function( i, type ) {
	jQuery.fn[ type ] = function( fn ) {
		return this.on( type, fn );
	};
});




jQuery.expr.filters.animated = function( elem ) {
	return jQuery.grep(jQuery.timers, function( fn ) {
		return elem === fn.elem;
	}).length;
};





var docElem = window.document.documentElement;

/**
 * Gets a window from an element
 */
function getWindow( elem ) {
	return jQuery.isWindow( elem ) ?
		elem :
		elem.nodeType === 9 ?
			elem.defaultView || elem.parentWindow :
			false;
}

jQuery.offset = {
	setOffset: function( elem, options, i ) {
		var curPosition, curLeft, curCSSTop, curTop, curOffset, curCSSLeft, calculatePosition,
			position = jQuery.css( elem, "position" ),
			curElem = jQuery( elem ),
			props = {};

		// set position first, in-case top/left are set even on static elem
		if ( position === "static" ) {
			elem.style.position = "relative";
		}

		curOffset = curElem.offset();
		curCSSTop = jQuery.css( elem, "top" );
		curCSSLeft = jQuery.css( elem, "left" );
		calculatePosition = ( position === "absolute" || position === "fixed" ) &&
			jQuery.inArray("auto", [ curCSSTop, curCSSLeft ] ) > -1;

		// need to be able to calculate position if either top or left is auto and position is either absolute or fixed
		if ( calculatePosition ) {
			curPosition = curElem.position();
			curTop = curPosition.top;
			curLeft = curPosition.left;
		} else {
			curTop = parseFloat( curCSSTop ) || 0;
			curLeft = parseFloat( curCSSLeft ) || 0;
		}

		if ( jQuery.isFunction( options ) ) {
			options = options.call( elem, i, curOffset );
		}

		if ( options.top != null ) {
			props.top = ( options.top - curOffset.top ) + curTop;
		}
		if ( options.left != null ) {
			props.left = ( options.left - curOffset.left ) + curLeft;
		}

		if ( "using" in options ) {
			options.using.call( elem, props );
		} else {
			curElem.css( props );
		}
	}
};

jQuery.fn.extend({
	offset: function( options ) {
		if ( arguments.length ) {
			return options === undefined ?
				this :
				this.each(function( i ) {
					jQuery.offset.setOffset( this, options, i );
				});
		}

		var docElem, win,
			box = { top: 0, left: 0 },
			elem = this[ 0 ],
			doc = elem && elem.ownerDocument;

		if ( !doc ) {
			return;
		}

		docElem = doc.documentElement;

		// Make sure it's not a disconnected DOM node
		if ( !jQuery.contains( docElem, elem ) ) {
			return box;
		}

		// If we don't have gBCR, just use 0,0 rather than error
		// BlackBerry 5, iOS 3 (original iPhone)
		if ( typeof elem.getBoundingClientRect !== strundefined ) {
			box = elem.getBoundingClientRect();
		}
		win = getWindow( doc );
		return {
			top: box.top  + ( win.pageYOffset || docElem.scrollTop )  - ( docElem.clientTop  || 0 ),
			left: box.left + ( win.pageXOffset || docElem.scrollLeft ) - ( docElem.clientLeft || 0 )
		};
	},

	position: function() {
		if ( !this[ 0 ] ) {
			return;
		}

		var offsetParent, offset,
			parentOffset = { top: 0, left: 0 },
			elem = this[ 0 ];

		// fixed elements are offset from window (parentOffset = {top:0, left: 0}, because it is its only offset parent
		if ( jQuery.css( elem, "position" ) === "fixed" ) {
			// we assume that getBoundingClientRect is available when computed position is fixed
			offset = elem.getBoundingClientRect();
		} else {
			// Get *real* offsetParent
			offsetParent = this.offsetParent();

			// Get correct offsets
			offset = this.offset();
			if ( !jQuery.nodeName( offsetParent[ 0 ], "html" ) ) {
				parentOffset = offsetParent.offset();
			}

			// Add offsetParent borders
			parentOffset.top  += jQuery.css( offsetParent[ 0 ], "borderTopWidth", true );
			parentOffset.left += jQuery.css( offsetParent[ 0 ], "borderLeftWidth", true );
		}

		// Subtract parent offsets and element margins
		// note: when an element has margin: auto the offsetLeft and marginLeft
		// are the same in Safari causing offset.left to incorrectly be 0
		return {
			top:  offset.top  - parentOffset.top - jQuery.css( elem, "marginTop", true ),
			left: offset.left - parentOffset.left - jQuery.css( elem, "marginLeft", true)
		};
	},

	offsetParent: function() {
		return this.map(function() {
			var offsetParent = this.offsetParent || docElem;

			while ( offsetParent && ( !jQuery.nodeName( offsetParent, "html" ) && jQuery.css( offsetParent, "position" ) === "static" ) ) {
				offsetParent = offsetParent.offsetParent;
			}
			return offsetParent || docElem;
		});
	}
});

// Create scrollLeft and scrollTop methods
jQuery.each( { scrollLeft: "pageXOffset", scrollTop: "pageYOffset" }, function( method, prop ) {
	var top = /Y/.test( prop );

	jQuery.fn[ method ] = function( val ) {
		return access( this, function( elem, method, val ) {
			var win = getWindow( elem );

			if ( val === undefined ) {
				return win ? (prop in win) ? win[ prop ] :
					win.document.documentElement[ method ] :
					elem[ method ];
			}

			if ( win ) {
				win.scrollTo(
					!top ? val : jQuery( win ).scrollLeft(),
					top ? val : jQuery( win ).scrollTop()
				);

			} else {
				elem[ method ] = val;
			}
		}, method, val, arguments.length, null );
	};
});

// Add the top/left cssHooks using jQuery.fn.position
// Webkit bug: https://bugs.webkit.org/show_bug.cgi?id=29084
// getComputedStyle returns percent when specified for top/left/bottom/right
// rather than make the css module depend on the offset module, we just check for it here
jQuery.each( [ "top", "left" ], function( i, prop ) {
	jQuery.cssHooks[ prop ] = addGetHookIf( support.pixelPosition,
		function( elem, computed ) {
			if ( computed ) {
				computed = curCSS( elem, prop );
				// if curCSS returns percentage, fallback to offset
				return rnumnonpx.test( computed ) ?
					jQuery( elem ).position()[ prop ] + "px" :
					computed;
			}
		}
	);
});


// Create innerHeight, innerWidth, height, width, outerHeight and outerWidth methods
jQuery.each( { Height: "height", Width: "width" }, function( name, type ) {
	jQuery.each( { padding: "inner" + name, content: type, "": "outer" + name }, function( defaultExtra, funcName ) {
		// margin is only for outerHeight, outerWidth
		jQuery.fn[ funcName ] = function( margin, value ) {
			var chainable = arguments.length && ( defaultExtra || typeof margin !== "boolean" ),
				extra = defaultExtra || ( margin === true || value === true ? "margin" : "border" );

			return access( this, function( elem, type, value ) {
				var doc;

				if ( jQuery.isWindow( elem ) ) {
					// As of 5/8/2012 this will yield incorrect results for Mobile Safari, but there
					// isn't a whole lot we can do. See pull request at this URL for discussion:
					// https://github.com/jquery/jquery/pull/764
					return elem.document.documentElement[ "client" + name ];
				}

				// Get document width or height
				if ( elem.nodeType === 9 ) {
					doc = elem.documentElement;

					// Either scroll[Width/Height] or offset[Width/Height] or client[Width/Height], whichever is greatest
					// unfortunately, this causes bug #3838 in IE6/8 only, but there is currently no good, small way to fix it.
					return Math.max(
						elem.body[ "scroll" + name ], doc[ "scroll" + name ],
						elem.body[ "offset" + name ], doc[ "offset" + name ],
						doc[ "client" + name ]
					);
				}

				return value === undefined ?
					// Get width or height on the element, requesting but not forcing parseFloat
					jQuery.css( elem, type, extra ) :

					// Set width or height on the element
					jQuery.style( elem, type, value, extra );
			}, type, chainable ? margin : undefined, chainable, null );
		};
	});
});


// The number of elements contained in the matched element set
jQuery.fn.size = function() {
	return this.length;
};

jQuery.fn.andSelf = jQuery.fn.addBack;




// Register as a named AMD module, since jQuery can be concatenated with other
// files that may use define, but not via a proper concatenation script that
// understands anonymous AMD modules. A named AMD is safest and most robust
// way to register. Lowercase jquery is used because AMD module names are
// derived from file names, and jQuery is normally delivered in a lowercase
// file name. Do this after creating the global so that if an AMD module wants
// to call noConflict to hide this version of jQuery, it will work.

// Note that for maximum portability, libraries that are not jQuery should
// declare themselves as anonymous modules, and avoid setting a global if an
// AMD loader is present. jQuery is a special case. For more information, see
// https://github.com/jrburke/requirejs/wiki/Updating-existing-libraries#wiki-anon

if ( typeof define === "function" && define.amd ) {
	define( "jquery", [], function() {
		return jQuery;
	});
}




var
	// Map over jQuery in case of overwrite
	_jQuery = window.jQuery,

	// Map over the $ in case of overwrite
	_$ = window.$;

jQuery.noConflict = function( deep ) {
	if ( window.$ === jQuery ) {
		window.$ = _$;
	}

	if ( deep && window.jQuery === jQuery ) {
		window.jQuery = _jQuery;
	}

	return jQuery;
};

// Expose jQuery and $ identifiers, even in
// AMD (#7102#comment:10, https://github.com/jquery/jquery/pull/557)
// and CommonJS for browser emulators (#13566)
if ( typeof noGlobal === strundefined ) {
	window.jQuery = window.$ = jQuery;
}




return jQuery;

}));

/*!
 * Bootstrap v3.3.4 (http://getbootstrap.com)
 * Copyright 2011-2015 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 */

if (typeof jQuery === 'undefined') {
  throw new Error('Bootstrap\'s JavaScript requires jQuery')
}

+function ($) {
  'use strict';
  var version = $.fn.jquery.split(' ')[0].split('.')
  if ((version[0] < 2 && version[1] < 9) || (version[0] == 1 && version[1] == 9 && version[2] < 1)) {
    throw new Error('Bootstrap\'s JavaScript requires jQuery version 1.9.1 or higher')
  }
}(jQuery);

/* ========================================================================
 * Bootstrap: transition.js v3.3.4
 * http://getbootstrap.com/javascript/#transitions
 * ========================================================================
 * Copyright 2011-2015 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 * ======================================================================== */


+function ($) {
  'use strict';

  // CSS TRANSITION SUPPORT (Shoutout: http://www.modernizr.com/)
  // ============================================================

  function transitionEnd() {
    var el = document.createElement('bootstrap')

    var transEndEventNames = {
      WebkitTransition : 'webkitTransitionEnd',
      MozTransition    : 'transitionend',
      OTransition      : 'oTransitionEnd otransitionend',
      transition       : 'transitionend'
    }

    for (var name in transEndEventNames) {
      if (el.style[name] !== undefined) {
        return { end: transEndEventNames[name] }
      }
    }

    return false // explicit for ie8 (  ._.)
  }

  // http://blog.alexmaccaw.com/css-transitions
  $.fn.emulateTransitionEnd = function (duration) {
    var called = false
    var $el = this
    $(this).one('bsTransitionEnd', function () { called = true })
    var callback = function () { if (!called) $($el).trigger($.support.transition.end) }
    setTimeout(callback, duration)
    return this
  }

  $(function () {
    $.support.transition = transitionEnd()

    if (!$.support.transition) return

    $.event.special.bsTransitionEnd = {
      bindType: $.support.transition.end,
      delegateType: $.support.transition.end,
      handle: function (e) {
        if ($(e.target).is(this)) return e.handleObj.handler.apply(this, arguments)
      }
    }
  })

}(jQuery);

/* ========================================================================
 * Bootstrap: alert.js v3.3.4
 * http://getbootstrap.com/javascript/#alerts
 * ========================================================================
 * Copyright 2011-2015 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 * ======================================================================== */


+function ($) {
  'use strict';

  // ALERT CLASS DEFINITION
  // ======================

  var dismiss = '[data-dismiss="alert"]'
  var Alert   = function (el) {
    $(el).on('click', dismiss, this.close)
  }

  Alert.VERSION = '3.3.4'

  Alert.TRANSITION_DURATION = 150

  Alert.prototype.close = function (e) {
    var $this    = $(this)
    var selector = $this.attr('data-target')

    if (!selector) {
      selector = $this.attr('href')
      selector = selector && selector.replace(/.*(?=#[^\s]*$)/, '') // strip for ie7
    }

    var $parent = $(selector)

    if (e) e.preventDefault()

    if (!$parent.length) {
      $parent = $this.closest('.alert')
    }

    $parent.trigger(e = $.Event('close.bs.alert'))

    if (e.isDefaultPrevented()) return

    $parent.removeClass('in')

    function removeElement() {
      // detach from parent, fire event then clean up data
      $parent.detach().trigger('closed.bs.alert').remove()
    }

    $.support.transition && $parent.hasClass('fade') ?
      $parent
        .one('bsTransitionEnd', removeElement)
        .emulateTransitionEnd(Alert.TRANSITION_DURATION) :
      removeElement()
  }


  // ALERT PLUGIN DEFINITION
  // =======================

  function Plugin(option) {
    return this.each(function () {
      var $this = $(this)
      var data  = $this.data('bs.alert')

      if (!data) $this.data('bs.alert', (data = new Alert(this)))
      if (typeof option == 'string') data[option].call($this)
    })
  }

  var old = $.fn.alert

  $.fn.alert             = Plugin
  $.fn.alert.Constructor = Alert


  // ALERT NO CONFLICT
  // =================

  $.fn.alert.noConflict = function () {
    $.fn.alert = old
    return this
  }


  // ALERT DATA-API
  // ==============

  $(document).on('click.bs.alert.data-api', dismiss, Alert.prototype.close)

}(jQuery);

/* ========================================================================
 * Bootstrap: button.js v3.3.4
 * http://getbootstrap.com/javascript/#buttons
 * ========================================================================
 * Copyright 2011-2015 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 * ======================================================================== */


+function ($) {
  'use strict';

  // BUTTON PUBLIC CLASS DEFINITION
  // ==============================

  var Button = function (element, options) {
    this.$element  = $(element)
    this.options   = $.extend({}, Button.DEFAULTS, options)
    this.isLoading = false
  }

  Button.VERSION  = '3.3.4'

  Button.DEFAULTS = {
    loadingText: 'loading...'
  }

  Button.prototype.setState = function (state) {
    var d    = 'disabled'
    var $el  = this.$element
    var val  = $el.is('input') ? 'val' : 'html'
    var data = $el.data()

    state = state + 'Text'

    if (data.resetText == null) $el.data('resetText', $el[val]())

    // push to event loop to allow forms to submit
    setTimeout($.proxy(function () {
      $el[val](data[state] == null ? this.options[state] : data[state])

      if (state == 'loadingText') {
        this.isLoading = true
        $el.addClass(d).attr(d, d)
      } else if (this.isLoading) {
        this.isLoading = false
        $el.removeClass(d).removeAttr(d)
      }
    }, this), 0)
  }

  Button.prototype.toggle = function () {
    var changed = true
    var $parent = this.$element.closest('[data-toggle="buttons"]')

    if ($parent.length) {
      var $input = this.$element.find('input')
      if ($input.prop('type') == 'radio') {
        if ($input.prop('checked') && this.$element.hasClass('active')) changed = false
        else $parent.find('.active').removeClass('active')
      }
      if (changed) $input.prop('checked', !this.$element.hasClass('active')).trigger('change')
    } else {
      this.$element.attr('aria-pressed', !this.$element.hasClass('active'))
    }

    if (changed) this.$element.toggleClass('active')
  }


  // BUTTON PLUGIN DEFINITION
  // ========================

  function Plugin(option) {
    return this.each(function () {
      var $this   = $(this)
      var data    = $this.data('bs.button')
      var options = typeof option == 'object' && option

      if (!data) $this.data('bs.button', (data = new Button(this, options)))

      if (option == 'toggle') data.toggle()
      else if (option) data.setState(option)
    })
  }

  var old = $.fn.button

  $.fn.button             = Plugin
  $.fn.button.Constructor = Button


  // BUTTON NO CONFLICT
  // ==================

  $.fn.button.noConflict = function () {
    $.fn.button = old
    return this
  }


  // BUTTON DATA-API
  // ===============

  $(document)
    .on('click.bs.button.data-api', '[data-toggle^="button"]', function (e) {
      var $btn = $(e.target)
      if (!$btn.hasClass('btn')) $btn = $btn.closest('.btn')
      Plugin.call($btn, 'toggle')
      e.preventDefault()
    })
    .on('focus.bs.button.data-api blur.bs.button.data-api', '[data-toggle^="button"]', function (e) {
      $(e.target).closest('.btn').toggleClass('focus', /^focus(in)?$/.test(e.type))
    })

}(jQuery);

/* ========================================================================
 * Bootstrap: carousel.js v3.3.4
 * http://getbootstrap.com/javascript/#carousel
 * ========================================================================
 * Copyright 2011-2015 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 * ======================================================================== */


+function ($) {
  'use strict';

  // CAROUSEL CLASS DEFINITION
  // =========================

  var Carousel = function (element, options) {
    this.$element    = $(element)
    this.$indicators = this.$element.find('.carousel-indicators')
    this.options     = options
    this.paused      = null
    this.sliding     = null
    this.interval    = null
    this.$active     = null
    this.$items      = null

    this.options.keyboard && this.$element.on('keydown.bs.carousel', $.proxy(this.keydown, this))

    this.options.pause == 'hover' && !('ontouchstart' in document.documentElement) && this.$element
      .on('mouseenter.bs.carousel', $.proxy(this.pause, this))
      .on('mouseleave.bs.carousel', $.proxy(this.cycle, this))
  }

  Carousel.VERSION  = '3.3.4'

  Carousel.TRANSITION_DURATION = 600

  Carousel.DEFAULTS = {
    interval: 5000,
    pause: 'hover',
    wrap: true,
    keyboard: true
  }

  Carousel.prototype.keydown = function (e) {
    if (/input|textarea/i.test(e.target.tagName)) return
    switch (e.which) {
      case 37: this.prev(); break
      case 39: this.next(); break
      default: return
    }

    e.preventDefault()
  }

  Carousel.prototype.cycle = function (e) {
    e || (this.paused = false)

    this.interval && clearInterval(this.interval)

    this.options.interval
      && !this.paused
      && (this.interval = setInterval($.proxy(this.next, this), this.options.interval))

    return this
  }

  Carousel.prototype.getItemIndex = function (item) {
    this.$items = item.parent().children('.item')
    return this.$items.index(item || this.$active)
  }

  Carousel.prototype.getItemForDirection = function (direction, active) {
    var activeIndex = this.getItemIndex(active)
    var willWrap = (direction == 'prev' && activeIndex === 0)
                || (direction == 'next' && activeIndex == (this.$items.length - 1))
    if (willWrap && !this.options.wrap) return active
    var delta = direction == 'prev' ? -1 : 1
    var itemIndex = (activeIndex + delta) % this.$items.length
    return this.$items.eq(itemIndex)
  }

  Carousel.prototype.to = function (pos) {
    var that        = this
    var activeIndex = this.getItemIndex(this.$active = this.$element.find('.item.active'))

    if (pos > (this.$items.length - 1) || pos < 0) return

    if (this.sliding)       return this.$element.one('slid.bs.carousel', function () { that.to(pos) }) // yes, "slid"
    if (activeIndex == pos) return this.pause().cycle()

    return this.slide(pos > activeIndex ? 'next' : 'prev', this.$items.eq(pos))
  }

  Carousel.prototype.pause = function (e) {
    e || (this.paused = true)

    if (this.$element.find('.next, .prev').length && $.support.transition) {
      this.$element.trigger($.support.transition.end)
      this.cycle(true)
    }

    this.interval = clearInterval(this.interval)

    return this
  }

  Carousel.prototype.next = function () {
    if (this.sliding) return
    return this.slide('next')
  }

  Carousel.prototype.prev = function () {
    if (this.sliding) return
    return this.slide('prev')
  }

  Carousel.prototype.slide = function (type, next) {
    var $active   = this.$element.find('.item.active')
    var $next     = next || this.getItemForDirection(type, $active)
    var isCycling = this.interval
    var direction = type == 'next' ? 'left' : 'right'
    var that      = this

    if ($next.hasClass('active')) return (this.sliding = false)

    var relatedTarget = $next[0]
    var slideEvent = $.Event('slide.bs.carousel', {
      relatedTarget: relatedTarget,
      direction: direction
    })
    this.$element.trigger(slideEvent)
    if (slideEvent.isDefaultPrevented()) return

    this.sliding = true

    isCycling && this.pause()

    if (this.$indicators.length) {
      this.$indicators.find('.active').removeClass('active')
      var $nextIndicator = $(this.$indicators.children()[this.getItemIndex($next)])
      $nextIndicator && $nextIndicator.addClass('active')
    }

    var slidEvent = $.Event('slid.bs.carousel', { relatedTarget: relatedTarget, direction: direction }) // yes, "slid"
    if ($.support.transition && this.$element.hasClass('slide')) {
      $next.addClass(type)
      $next[0].offsetWidth // force reflow
      $active.addClass(direction)
      $next.addClass(direction)
      $active
        .one('bsTransitionEnd', function () {
          $next.removeClass([type, direction].join(' ')).addClass('active')
          $active.removeClass(['active', direction].join(' '))
          that.sliding = false
          setTimeout(function () {
            that.$element.trigger(slidEvent)
          }, 0)
        })
        .emulateTransitionEnd(Carousel.TRANSITION_DURATION)
    } else {
      $active.removeClass('active')
      $next.addClass('active')
      this.sliding = false
      this.$element.trigger(slidEvent)
    }

    isCycling && this.cycle()

    return this
  }


  // CAROUSEL PLUGIN DEFINITION
  // ==========================

  function Plugin(option) {
    return this.each(function () {
      var $this   = $(this)
      var data    = $this.data('bs.carousel')
      var options = $.extend({}, Carousel.DEFAULTS, $this.data(), typeof option == 'object' && option)
      var action  = typeof option == 'string' ? option : options.slide

      if (!data) $this.data('bs.carousel', (data = new Carousel(this, options)))
      if (typeof option == 'number') data.to(option)
      else if (action) data[action]()
      else if (options.interval) data.pause().cycle()
    })
  }

  var old = $.fn.carousel

  $.fn.carousel             = Plugin
  $.fn.carousel.Constructor = Carousel


  // CAROUSEL NO CONFLICT
  // ====================

  $.fn.carousel.noConflict = function () {
    $.fn.carousel = old
    return this
  }


  // CAROUSEL DATA-API
  // =================

  var clickHandler = function (e) {
    var href
    var $this   = $(this)
    var $target = $($this.attr('data-target') || (href = $this.attr('href')) && href.replace(/.*(?=#[^\s]+$)/, '')) // strip for ie7
    if (!$target.hasClass('carousel')) return
    var options = $.extend({}, $target.data(), $this.data())
    var slideIndex = $this.attr('data-slide-to')
    if (slideIndex) options.interval = false

    Plugin.call($target, options)

    if (slideIndex) {
      $target.data('bs.carousel').to(slideIndex)
    }

    e.preventDefault()
  }

  $(document)
    .on('click.bs.carousel.data-api', '[data-slide]', clickHandler)
    .on('click.bs.carousel.data-api', '[data-slide-to]', clickHandler)

  $(window).on('load', function () {
    $('[data-ride="carousel"]').each(function () {
      var $carousel = $(this)
      Plugin.call($carousel, $carousel.data())
    })
  })

}(jQuery);

/* ========================================================================
 * Bootstrap: collapse.js v3.3.4
 * http://getbootstrap.com/javascript/#collapse
 * ========================================================================
 * Copyright 2011-2015 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 * ======================================================================== */


+function ($) {
  'use strict';

  // COLLAPSE PUBLIC CLASS DEFINITION
  // ================================

  var Collapse = function (element, options) {
    this.$element      = $(element)
    this.options       = $.extend({}, Collapse.DEFAULTS, options)
    this.$trigger      = $('[data-toggle="collapse"][href="#' + element.id + '"],' +
                           '[data-toggle="collapse"][data-target="#' + element.id + '"]')
    this.transitioning = null

    if (this.options.parent) {
      this.$parent = this.getParent()
    } else {
      this.addAriaAndCollapsedClass(this.$element, this.$trigger)
    }

    if (this.options.toggle) this.toggle()
  }

  Collapse.VERSION  = '3.3.4'

  Collapse.TRANSITION_DURATION = 350

  Collapse.DEFAULTS = {
    toggle: true
  }

  Collapse.prototype.dimension = function () {
    var hasWidth = this.$element.hasClass('width')
    return hasWidth ? 'width' : 'height'
  }

  Collapse.prototype.show = function () {
    if (this.transitioning || this.$element.hasClass('in')) return

    var activesData
    var actives = this.$parent && this.$parent.children('.panel').children('.in, .collapsing')

    if (actives && actives.length) {
      activesData = actives.data('bs.collapse')
      if (activesData && activesData.transitioning) return
    }

    var startEvent = $.Event('show.bs.collapse')
    this.$element.trigger(startEvent)
    if (startEvent.isDefaultPrevented()) return

    if (actives && actives.length) {
      Plugin.call(actives, 'hide')
      activesData || actives.data('bs.collapse', null)
    }

    var dimension = this.dimension()

    this.$element
      .removeClass('collapse')
      .addClass('collapsing')[dimension](0)
      .attr('aria-expanded', true)

    this.$trigger
      .removeClass('collapsed')
      .attr('aria-expanded', true)

    this.transitioning = 1

    var complete = function () {
      this.$element
        .removeClass('collapsing')
        .addClass('collapse in')[dimension]('')
      this.transitioning = 0
      this.$element
        .trigger('shown.bs.collapse')
    }

    if (!$.support.transition) return complete.call(this)

    var scrollSize = $.camelCase(['scroll', dimension].join('-'))

    this.$element
      .one('bsTransitionEnd', $.proxy(complete, this))
      .emulateTransitionEnd(Collapse.TRANSITION_DURATION)[dimension](this.$element[0][scrollSize])
  }

  Collapse.prototype.hide = function () {
    if (this.transitioning || !this.$element.hasClass('in')) return

    var startEvent = $.Event('hide.bs.collapse')
    this.$element.trigger(startEvent)
    if (startEvent.isDefaultPrevented()) return

    var dimension = this.dimension()

    this.$element[dimension](this.$element[dimension]())[0].offsetHeight

    this.$element
      .addClass('collapsing')
      .removeClass('collapse in')
      .attr('aria-expanded', false)

    this.$trigger
      .addClass('collapsed')
      .attr('aria-expanded', false)

    this.transitioning = 1

    var complete = function () {
      this.transitioning = 0
      this.$element
        .removeClass('collapsing')
        .addClass('collapse')
        .trigger('hidden.bs.collapse')
    }

    if (!$.support.transition) return complete.call(this)

    this.$element
      [dimension](0)
      .one('bsTransitionEnd', $.proxy(complete, this))
      .emulateTransitionEnd(Collapse.TRANSITION_DURATION)
  }

  Collapse.prototype.toggle = function () {
    this[this.$element.hasClass('in') ? 'hide' : 'show']()
  }

  Collapse.prototype.getParent = function () {
    return $(this.options.parent)
      .find('[data-toggle="collapse"][data-parent="' + this.options.parent + '"]')
      .each($.proxy(function (i, element) {
        var $element = $(element)
        this.addAriaAndCollapsedClass(getTargetFromTrigger($element), $element)
      }, this))
      .end()
  }

  Collapse.prototype.addAriaAndCollapsedClass = function ($element, $trigger) {
    var isOpen = $element.hasClass('in')

    $element.attr('aria-expanded', isOpen)
    $trigger
      .toggleClass('collapsed', !isOpen)
      .attr('aria-expanded', isOpen)
  }

  function getTargetFromTrigger($trigger) {
    var href
    var target = $trigger.attr('data-target')
      || (href = $trigger.attr('href')) && href.replace(/.*(?=#[^\s]+$)/, '') // strip for ie7

    return $(target)
  }


  // COLLAPSE PLUGIN DEFINITION
  // ==========================

  function Plugin(option) {
    return this.each(function () {
      var $this   = $(this)
      var data    = $this.data('bs.collapse')
      var options = $.extend({}, Collapse.DEFAULTS, $this.data(), typeof option == 'object' && option)

      if (!data && options.toggle && /show|hide/.test(option)) options.toggle = false
      if (!data) $this.data('bs.collapse', (data = new Collapse(this, options)))
      if (typeof option == 'string') data[option]()
    })
  }

  var old = $.fn.collapse

  $.fn.collapse             = Plugin
  $.fn.collapse.Constructor = Collapse


  // COLLAPSE NO CONFLICT
  // ====================

  $.fn.collapse.noConflict = function () {
    $.fn.collapse = old
    return this
  }


  // COLLAPSE DATA-API
  // =================

  $(document).on('click.bs.collapse.data-api', '[data-toggle="collapse"]', function (e) {
    var $this   = $(this)

    if (!$this.attr('data-target')) e.preventDefault()

    var $target = getTargetFromTrigger($this)
    var data    = $target.data('bs.collapse')
    var option  = data ? 'toggle' : $this.data()

    Plugin.call($target, option)
  })

}(jQuery);

/* ========================================================================
 * Bootstrap: dropdown.js v3.3.4
 * http://getbootstrap.com/javascript/#dropdowns
 * ========================================================================
 * Copyright 2011-2015 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 * ======================================================================== */


+function ($) {
  'use strict';

  // DROPDOWN CLASS DEFINITION
  // =========================

  var backdrop = '.dropdown-backdrop'
  var toggle   = '[data-toggle="dropdown"]'
  var Dropdown = function (element) {
    $(element).on('click.bs.dropdown', this.toggle)
  }

  Dropdown.VERSION = '3.3.4'

  Dropdown.prototype.toggle = function (e) {
    var $this = $(this)

    if ($this.is('.disabled, :disabled')) return

    var $parent  = getParent($this)
    var isActive = $parent.hasClass('open')

    clearMenus()

    if (!isActive) {
      if ('ontouchstart' in document.documentElement && !$parent.closest('.navbar-nav').length) {
        // if mobile we use a backdrop because click events don't delegate
        $('<div class="dropdown-backdrop"/>').insertAfter($(this)).on('click', clearMenus)
      }

      var relatedTarget = { relatedTarget: this }
      $parent.trigger(e = $.Event('show.bs.dropdown', relatedTarget))

      if (e.isDefaultPrevented()) return

      $this
        .trigger('focus')
        .attr('aria-expanded', 'true')

      $parent
        .toggleClass('open')
        .trigger('shown.bs.dropdown', relatedTarget)
    }

    return false
  }

  Dropdown.prototype.keydown = function (e) {
    if (!/(38|40|27|32)/.test(e.which) || /input|textarea/i.test(e.target.tagName)) return

    var $this = $(this)

    e.preventDefault()
    e.stopPropagation()

    if ($this.is('.disabled, :disabled')) return

    var $parent  = getParent($this)
    var isActive = $parent.hasClass('open')

    if ((!isActive && e.which != 27) || (isActive && e.which == 27)) {
      if (e.which == 27) $parent.find(toggle).trigger('focus')
      return $this.trigger('click')
    }

    var desc = ' li:not(.disabled):visible a'
    var $items = $parent.find('[role="menu"]' + desc + ', [role="listbox"]' + desc)

    if (!$items.length) return

    var index = $items.index(e.target)

    if (e.which == 38 && index > 0)                 index--                        // up
    if (e.which == 40 && index < $items.length - 1) index++                        // down
    if (!~index)                                      index = 0

    $items.eq(index).trigger('focus')
  }

  function clearMenus(e) {
    if (e && e.which === 3) return
    $(backdrop).remove()
    $(toggle).each(function () {
      var $this         = $(this)
      var $parent       = getParent($this)
      var relatedTarget = { relatedTarget: this }

      if (!$parent.hasClass('open')) return

      $parent.trigger(e = $.Event('hide.bs.dropdown', relatedTarget))

      if (e.isDefaultPrevented()) return

      $this.attr('aria-expanded', 'false')
      $parent.removeClass('open').trigger('hidden.bs.dropdown', relatedTarget)
    })
  }

  function getParent($this) {
    var selector = $this.attr('data-target')

    if (!selector) {
      selector = $this.attr('href')
      selector = selector && /#[A-Za-z]/.test(selector) && selector.replace(/.*(?=#[^\s]*$)/, '') // strip for ie7
    }

    var $parent = selector && $(selector)

    return $parent && $parent.length ? $parent : $this.parent()
  }


  // DROPDOWN PLUGIN DEFINITION
  // ==========================

  function Plugin(option) {
    return this.each(function () {
      var $this = $(this)
      var data  = $this.data('bs.dropdown')

      if (!data) $this.data('bs.dropdown', (data = new Dropdown(this)))
      if (typeof option == 'string') data[option].call($this)
    })
  }

  var old = $.fn.dropdown

  $.fn.dropdown             = Plugin
  $.fn.dropdown.Constructor = Dropdown


  // DROPDOWN NO CONFLICT
  // ====================

  $.fn.dropdown.noConflict = function () {
    $.fn.dropdown = old
    return this
  }


  // APPLY TO STANDARD DROPDOWN ELEMENTS
  // ===================================

  $(document)
    .on('click.bs.dropdown.data-api', clearMenus)
    .on('click.bs.dropdown.data-api', '.dropdown form', function (e) { e.stopPropagation() })
    .on('click.bs.dropdown.data-api', toggle, Dropdown.prototype.toggle)
    .on('keydown.bs.dropdown.data-api', toggle, Dropdown.prototype.keydown)
    .on('keydown.bs.dropdown.data-api', '[role="menu"]', Dropdown.prototype.keydown)
    .on('keydown.bs.dropdown.data-api', '[role="listbox"]', Dropdown.prototype.keydown)

}(jQuery);

/* ========================================================================
 * Bootstrap: modal.js v3.3.4
 * http://getbootstrap.com/javascript/#modals
 * ========================================================================
 * Copyright 2011-2015 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 * ======================================================================== */


+function ($) {
  'use strict';

  // MODAL CLASS DEFINITION
  // ======================

  var Modal = function (element, options) {
    this.options             = options
    this.$body               = $(document.body)
    this.$element            = $(element)
    this.$dialog             = this.$element.find('.modal-dialog')
    this.$backdrop           = null
    this.isShown             = null
    this.originalBodyPad     = null
    this.scrollbarWidth      = 0
    this.ignoreBackdropClick = false

    if (this.options.remote) {
      this.$element
        .find('.modal-content')
        .load(this.options.remote, $.proxy(function () {
          this.$element.trigger('loaded.bs.modal')
        }, this))
    }
  }

  Modal.VERSION  = '3.3.4'

  Modal.TRANSITION_DURATION = 300
  Modal.BACKDROP_TRANSITION_DURATION = 150

  Modal.DEFAULTS = {
    backdrop: true,
    keyboard: true,
    show: true
  }

  Modal.prototype.toggle = function (_relatedTarget) {
    return this.isShown ? this.hide() : this.show(_relatedTarget)
  }

  Modal.prototype.show = function (_relatedTarget) {
    var that = this
    var e    = $.Event('show.bs.modal', { relatedTarget: _relatedTarget })

    this.$element.trigger(e)

    if (this.isShown || e.isDefaultPrevented()) return

    this.isShown = true

    this.checkScrollbar()
    this.setScrollbar()
    this.$body.addClass('modal-open')

    this.escape()
    this.resize()

    this.$element.on('click.dismiss.bs.modal', '[data-dismiss="modal"]', $.proxy(this.hide, this))

    this.$dialog.on('mousedown.dismiss.bs.modal', function () {
      that.$element.one('mouseup.dismiss.bs.modal', function (e) {
        if ($(e.target).is(that.$element)) that.ignoreBackdropClick = true
      })
    })

    this.backdrop(function () {
      var transition = $.support.transition && that.$element.hasClass('fade')

      if (!that.$element.parent().length) {
        that.$element.appendTo(that.$body) // don't move modals dom position
      }

      that.$element
        .show()
        .scrollTop(0)

      that.adjustDialog()

      if (transition) {
        that.$element[0].offsetWidth // force reflow
      }

      that.$element
        .addClass('in')
        .attr('aria-hidden', false)

      that.enforceFocus()

      var e = $.Event('shown.bs.modal', { relatedTarget: _relatedTarget })

      transition ?
        that.$dialog // wait for modal to slide in
          .one('bsTransitionEnd', function () {
            that.$element.trigger('focus').trigger(e)
          })
          .emulateTransitionEnd(Modal.TRANSITION_DURATION) :
        that.$element.trigger('focus').trigger(e)
    })
  }

  Modal.prototype.hide = function (e) {
    if (e) e.preventDefault()

    e = $.Event('hide.bs.modal')

    this.$element.trigger(e)

    if (!this.isShown || e.isDefaultPrevented()) return

    this.isShown = false

    this.escape()
    this.resize()

    $(document).off('focusin.bs.modal')

    this.$element
      .removeClass('in')
      .attr('aria-hidden', true)
      .off('click.dismiss.bs.modal')
      .off('mouseup.dismiss.bs.modal')

    this.$dialog.off('mousedown.dismiss.bs.modal')

    $.support.transition && this.$element.hasClass('fade') ?
      this.$element
        .one('bsTransitionEnd', $.proxy(this.hideModal, this))
        .emulateTransitionEnd(Modal.TRANSITION_DURATION) :
      this.hideModal()
  }

  Modal.prototype.enforceFocus = function () {
    $(document)
      .off('focusin.bs.modal') // guard against infinite focus loop
      .on('focusin.bs.modal', $.proxy(function (e) {
        if (this.$element[0] !== e.target && !this.$element.has(e.target).length) {
          this.$element.trigger('focus')
        }
      }, this))
  }

  Modal.prototype.escape = function () {
    if (this.isShown && this.options.keyboard) {
      this.$element.on('keydown.dismiss.bs.modal', $.proxy(function (e) {
        e.which == 27 && this.hide()
      }, this))
    } else if (!this.isShown) {
      this.$element.off('keydown.dismiss.bs.modal')
    }
  }

  Modal.prototype.resize = function () {
    if (this.isShown) {
      $(window).on('resize.bs.modal', $.proxy(this.handleUpdate, this))
    } else {
      $(window).off('resize.bs.modal')
    }
  }

  Modal.prototype.hideModal = function () {
    var that = this
    this.$element.hide()
    this.backdrop(function () {
      that.$body.removeClass('modal-open')
      that.resetAdjustments()
      that.resetScrollbar()
      that.$element.trigger('hidden.bs.modal')
    })
  }

  Modal.prototype.removeBackdrop = function () {
    this.$backdrop && this.$backdrop.remove()
    this.$backdrop = null
  }

  Modal.prototype.backdrop = function (callback) {
    var that = this
    var animate = this.$element.hasClass('fade') ? 'fade' : ''

    if (this.isShown && this.options.backdrop) {
      var doAnimate = $.support.transition && animate

      this.$backdrop = $('<div class="modal-backdrop ' + animate + '" />')
        .appendTo(this.$body)

      this.$element.on('click.dismiss.bs.modal', $.proxy(function (e) {
        if (this.ignoreBackdropClick) {
          this.ignoreBackdropClick = false
          return
        }
        if (e.target !== e.currentTarget) return
        this.options.backdrop == 'static'
          ? this.$element[0].focus()
          : this.hide()
      }, this))

      if (doAnimate) this.$backdrop[0].offsetWidth // force reflow

      this.$backdrop.addClass('in')

      if (!callback) return

      doAnimate ?
        this.$backdrop
          .one('bsTransitionEnd', callback)
          .emulateTransitionEnd(Modal.BACKDROP_TRANSITION_DURATION) :
        callback()

    } else if (!this.isShown && this.$backdrop) {
      this.$backdrop.removeClass('in')

      var callbackRemove = function () {
        that.removeBackdrop()
        callback && callback()
      }
      $.support.transition && this.$element.hasClass('fade') ?
        this.$backdrop
          .one('bsTransitionEnd', callbackRemove)
          .emulateTransitionEnd(Modal.BACKDROP_TRANSITION_DURATION) :
        callbackRemove()

    } else if (callback) {
      callback()
    }
  }

  // these following methods are used to handle overflowing modals

  Modal.prototype.handleUpdate = function () {
    this.adjustDialog()
  }

  Modal.prototype.adjustDialog = function () {
    var modalIsOverflowing = this.$element[0].scrollHeight > document.documentElement.clientHeight

    this.$element.css({
      paddingLeft:  !this.bodyIsOverflowing && modalIsOverflowing ? this.scrollbarWidth : '',
      paddingRight: this.bodyIsOverflowing && !modalIsOverflowing ? this.scrollbarWidth : ''
    })
  }

  Modal.prototype.resetAdjustments = function () {
    this.$element.css({
      paddingLeft: '',
      paddingRight: ''
    })
  }

  Modal.prototype.checkScrollbar = function () {
    var fullWindowWidth = window.innerWidth
    if (!fullWindowWidth) { // workaround for missing window.innerWidth in IE8
      var documentElementRect = document.documentElement.getBoundingClientRect()
      fullWindowWidth = documentElementRect.right - Math.abs(documentElementRect.left)
    }
    this.bodyIsOverflowing = document.body.clientWidth < fullWindowWidth
    this.scrollbarWidth = this.measureScrollbar()
  }

  Modal.prototype.setScrollbar = function () {
    var bodyPad = parseInt((this.$body.css('padding-right') || 0), 10)
    this.originalBodyPad = document.body.style.paddingRight || ''
    if (this.bodyIsOverflowing) this.$body.css('padding-right', bodyPad + this.scrollbarWidth)
  }

  Modal.prototype.resetScrollbar = function () {
    this.$body.css('padding-right', this.originalBodyPad)
  }

  Modal.prototype.measureScrollbar = function () { // thx walsh
    var scrollDiv = document.createElement('div')
    scrollDiv.className = 'modal-scrollbar-measure'
    this.$body.append(scrollDiv)
    var scrollbarWidth = scrollDiv.offsetWidth - scrollDiv.clientWidth
    this.$body[0].removeChild(scrollDiv)
    return scrollbarWidth
  }


  // MODAL PLUGIN DEFINITION
  // =======================

  function Plugin(option, _relatedTarget) {
    return this.each(function () {
      var $this   = $(this)
      var data    = $this.data('bs.modal')
      var options = $.extend({}, Modal.DEFAULTS, $this.data(), typeof option == 'object' && option)

      if (!data) $this.data('bs.modal', (data = new Modal(this, options)))
      if (typeof option == 'string') data[option](_relatedTarget)
      else if (options.show) data.show(_relatedTarget)
    })
  }

  var old = $.fn.modal

  $.fn.modal             = Plugin
  $.fn.modal.Constructor = Modal


  // MODAL NO CONFLICT
  // =================

  $.fn.modal.noConflict = function () {
    $.fn.modal = old
    return this
  }


  // MODAL DATA-API
  // ==============

  $(document).on('click.bs.modal.data-api', '[data-toggle="modal"]', function (e) {
    var $this   = $(this)
    var href    = $this.attr('href')
    var $target = $($this.attr('data-target') || (href && href.replace(/.*(?=#[^\s]+$)/, ''))) // strip for ie7
    var option  = $target.data('bs.modal') ? 'toggle' : $.extend({ remote: !/#/.test(href) && href }, $target.data(), $this.data())

    if ($this.is('a')) e.preventDefault()

    $target.one('show.bs.modal', function (showEvent) {
      if (showEvent.isDefaultPrevented()) return // only register focus restorer if modal will actually get shown
      $target.one('hidden.bs.modal', function () {
        $this.is(':visible') && $this.trigger('focus')
      })
    })
    Plugin.call($target, option, this)
  })

}(jQuery);

/* ========================================================================
 * Bootstrap: tooltip.js v3.3.4
 * http://getbootstrap.com/javascript/#tooltip
 * Inspired by the original jQuery.tipsy by Jason Frame
 * ========================================================================
 * Copyright 2011-2015 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 * ======================================================================== */


+function ($) {
  'use strict';

  // TOOLTIP PUBLIC CLASS DEFINITION
  // ===============================

  var Tooltip = function (element, options) {
    this.type       = null
    this.options    = null
    this.enabled    = null
    this.timeout    = null
    this.hoverState = null
    this.$element   = null

    this.init('tooltip', element, options)
  }

  Tooltip.VERSION  = '3.3.4'

  Tooltip.TRANSITION_DURATION = 150

  Tooltip.DEFAULTS = {
    animation: true,
    placement: 'top',
    selector: false,
    template: '<div class="tooltip" role="tooltip"><div class="tooltip-arrow"></div><div class="tooltip-inner"></div></div>',
    trigger: 'hover focus',
    title: '',
    delay: 0,
    html: false,
    container: false,
    viewport: {
      selector: 'body',
      padding: 0
    }
  }

  Tooltip.prototype.init = function (type, element, options) {
    this.enabled   = true
    this.type      = type
    this.$element  = $(element)
    this.options   = this.getOptions(options)
    this.$viewport = this.options.viewport && $(this.options.viewport.selector || this.options.viewport)

    if (this.$element[0] instanceof document.constructor && !this.options.selector) {
      throw new Error('`selector` option must be specified when initializing ' + this.type + ' on the window.document object!')
    }

    var triggers = this.options.trigger.split(' ')

    for (var i = triggers.length; i--;) {
      var trigger = triggers[i]

      if (trigger == 'click') {
        this.$element.on('click.' + this.type, this.options.selector, $.proxy(this.toggle, this))
      } else if (trigger != 'manual') {
        var eventIn  = trigger == 'hover' ? 'mouseenter' : 'focusin'
        var eventOut = trigger == 'hover' ? 'mouseleave' : 'focusout'

        this.$element.on(eventIn  + '.' + this.type, this.options.selector, $.proxy(this.enter, this))
        this.$element.on(eventOut + '.' + this.type, this.options.selector, $.proxy(this.leave, this))
      }
    }

    this.options.selector ?
      (this._options = $.extend({}, this.options, { trigger: 'manual', selector: '' })) :
      this.fixTitle()
  }

  Tooltip.prototype.getDefaults = function () {
    return Tooltip.DEFAULTS
  }

  Tooltip.prototype.getOptions = function (options) {
    options = $.extend({}, this.getDefaults(), this.$element.data(), options)

    if (options.delay && typeof options.delay == 'number') {
      options.delay = {
        show: options.delay,
        hide: options.delay
      }
    }

    return options
  }

  Tooltip.prototype.getDelegateOptions = function () {
    var options  = {}
    var defaults = this.getDefaults()

    this._options && $.each(this._options, function (key, value) {
      if (defaults[key] != value) options[key] = value
    })

    return options
  }

  Tooltip.prototype.enter = function (obj) {
    var self = obj instanceof this.constructor ?
      obj : $(obj.currentTarget).data('bs.' + this.type)

    if (self && self.$tip && self.$tip.is(':visible')) {
      self.hoverState = 'in'
      return
    }

    if (!self) {
      self = new this.constructor(obj.currentTarget, this.getDelegateOptions())
      $(obj.currentTarget).data('bs.' + this.type, self)
    }

    clearTimeout(self.timeout)

    self.hoverState = 'in'

    if (!self.options.delay || !self.options.delay.show) return self.show()

    self.timeout = setTimeout(function () {
      if (self.hoverState == 'in') self.show()
    }, self.options.delay.show)
  }

  Tooltip.prototype.leave = function (obj) {
    var self = obj instanceof this.constructor ?
      obj : $(obj.currentTarget).data('bs.' + this.type)

    if (!self) {
      self = new this.constructor(obj.currentTarget, this.getDelegateOptions())
      $(obj.currentTarget).data('bs.' + this.type, self)
    }

    clearTimeout(self.timeout)

    self.hoverState = 'out'

    if (!self.options.delay || !self.options.delay.hide) return self.hide()

    self.timeout = setTimeout(function () {
      if (self.hoverState == 'out') self.hide()
    }, self.options.delay.hide)
  }

  Tooltip.prototype.show = function () {
    var e = $.Event('show.bs.' + this.type)

    if (this.hasContent() && this.enabled) {
      this.$element.trigger(e)

      var inDom = $.contains(this.$element[0].ownerDocument.documentElement, this.$element[0])
      if (e.isDefaultPrevented() || !inDom) return
      var that = this

      var $tip = this.tip()

      var tipId = this.getUID(this.type)

      this.setContent()
      $tip.attr('id', tipId)
      this.$element.attr('aria-describedby', tipId)

      if (this.options.animation) $tip.addClass('fade')

      var placement = typeof this.options.placement == 'function' ?
        this.options.placement.call(this, $tip[0], this.$element[0]) :
        this.options.placement

      var autoToken = /\s?auto?\s?/i
      var autoPlace = autoToken.test(placement)
      if (autoPlace) placement = placement.replace(autoToken, '') || 'top'

      $tip
        .detach()
        .css({ top: 0, left: 0, display: 'block' })
        .addClass(placement)
        .data('bs.' + this.type, this)

      this.options.container ? $tip.appendTo(this.options.container) : $tip.insertAfter(this.$element)

      var pos          = this.getPosition()
      var actualWidth  = $tip[0].offsetWidth
      var actualHeight = $tip[0].offsetHeight

      if (autoPlace) {
        var orgPlacement = placement
        var $container   = this.options.container ? $(this.options.container) : this.$element.parent()
        var containerDim = this.getPosition($container)

        placement = placement == 'bottom' && pos.bottom + actualHeight > containerDim.bottom ? 'top'    :
                    placement == 'top'    && pos.top    - actualHeight < containerDim.top    ? 'bottom' :
                    placement == 'right'  && pos.right  + actualWidth  > containerDim.width  ? 'left'   :
                    placement == 'left'   && pos.left   - actualWidth  < containerDim.left   ? 'right'  :
                    placement

        $tip
          .removeClass(orgPlacement)
          .addClass(placement)
      }

      var calculatedOffset = this.getCalculatedOffset(placement, pos, actualWidth, actualHeight)

      this.applyPlacement(calculatedOffset, placement)

      var complete = function () {
        var prevHoverState = that.hoverState
        that.$element.trigger('shown.bs.' + that.type)
        that.hoverState = null

        if (prevHoverState == 'out') that.leave(that)
      }

      $.support.transition && this.$tip.hasClass('fade') ?
        $tip
          .one('bsTransitionEnd', complete)
          .emulateTransitionEnd(Tooltip.TRANSITION_DURATION) :
        complete()
    }
  }

  Tooltip.prototype.applyPlacement = function (offset, placement) {
    var $tip   = this.tip()
    var width  = $tip[0].offsetWidth
    var height = $tip[0].offsetHeight

    // manually read margins because getBoundingClientRect includes difference
    var marginTop = parseInt($tip.css('margin-top'), 10)
    var marginLeft = parseInt($tip.css('margin-left'), 10)

    // we must check for NaN for ie 8/9
    if (isNaN(marginTop))  marginTop  = 0
    if (isNaN(marginLeft)) marginLeft = 0

    offset.top  = offset.top  + marginTop
    offset.left = offset.left + marginLeft

    // $.fn.offset doesn't round pixel values
    // so we use setOffset directly with our own function B-0
    $.offset.setOffset($tip[0], $.extend({
      using: function (props) {
        $tip.css({
          top: Math.round(props.top),
          left: Math.round(props.left)
        })
      }
    }, offset), 0)

    $tip.addClass('in')

    // check to see if placing tip in new offset caused the tip to resize itself
    var actualWidth  = $tip[0].offsetWidth
    var actualHeight = $tip[0].offsetHeight

    if (placement == 'top' && actualHeight != height) {
      offset.top = offset.top + height - actualHeight
    }

    var delta = this.getViewportAdjustedDelta(placement, offset, actualWidth, actualHeight)

    if (delta.left) offset.left += delta.left
    else offset.top += delta.top

    var isVertical          = /top|bottom/.test(placement)
    var arrowDelta          = isVertical ? delta.left * 2 - width + actualWidth : delta.top * 2 - height + actualHeight
    var arrowOffsetPosition = isVertical ? 'offsetWidth' : 'offsetHeight'

    $tip.offset(offset)
    this.replaceArrow(arrowDelta, $tip[0][arrowOffsetPosition], isVertical)
  }

  Tooltip.prototype.replaceArrow = function (delta, dimension, isVertical) {
    this.arrow()
      .css(isVertical ? 'left' : 'top', 50 * (1 - delta / dimension) + '%')
      .css(isVertical ? 'top' : 'left', '')
  }

  Tooltip.prototype.setContent = function () {
    var $tip  = this.tip()
    var title = this.getTitle()

    $tip.find('.tooltip-inner')[this.options.html ? 'html' : 'text'](title)
    $tip.removeClass('fade in top bottom left right')
  }

  Tooltip.prototype.hide = function (callback) {
    var that = this
    var $tip = $(this.$tip)
    var e    = $.Event('hide.bs.' + this.type)

    function complete() {
      if (that.hoverState != 'in') $tip.detach()
      that.$element
        .removeAttr('aria-describedby')
        .trigger('hidden.bs.' + that.type)
      callback && callback()
    }

    this.$element.trigger(e)

    if (e.isDefaultPrevented()) return

    $tip.removeClass('in')

    $.support.transition && $tip.hasClass('fade') ?
      $tip
        .one('bsTransitionEnd', complete)
        .emulateTransitionEnd(Tooltip.TRANSITION_DURATION) :
      complete()

    this.hoverState = null

    return this
  }

  Tooltip.prototype.fixTitle = function () {
    var $e = this.$element
    if ($e.attr('title') || typeof ($e.attr('data-original-title')) != 'string') {
      $e.attr('data-original-title', $e.attr('title') || '').attr('title', '')
    }
  }

  Tooltip.prototype.hasContent = function () {
    return this.getTitle()
  }

  Tooltip.prototype.getPosition = function ($element) {
    $element   = $element || this.$element

    var el     = $element[0]
    var isBody = el.tagName == 'BODY'

    var elRect    = el.getBoundingClientRect()
    if (elRect.width == null) {
      // width and height are missing in IE8, so compute them manually; see https://github.com/twbs/bootstrap/issues/14093
      elRect = $.extend({}, elRect, { width: elRect.right - elRect.left, height: elRect.bottom - elRect.top })
    }
    var elOffset  = isBody ? { top: 0, left: 0 } : $element.offset()
    var scroll    = { scroll: isBody ? document.documentElement.scrollTop || document.body.scrollTop : $element.scrollTop() }
    var outerDims = isBody ? { width: $(window).width(), height: $(window).height() } : null

    return $.extend({}, elRect, scroll, outerDims, elOffset)
  }

  Tooltip.prototype.getCalculatedOffset = function (placement, pos, actualWidth, actualHeight) {
    return placement == 'bottom' ? { top: pos.top + pos.height,   left: pos.left + pos.width / 2 - actualWidth / 2 } :
           placement == 'top'    ? { top: pos.top - actualHeight, left: pos.left + pos.width / 2 - actualWidth / 2 } :
           placement == 'left'   ? { top: pos.top + pos.height / 2 - actualHeight / 2, left: pos.left - actualWidth } :
        /* placement == 'right' */ { top: pos.top + pos.height / 2 - actualHeight / 2, left: pos.left + pos.width }

  }

  Tooltip.prototype.getViewportAdjustedDelta = function (placement, pos, actualWidth, actualHeight) {
    var delta = { top: 0, left: 0 }
    if (!this.$viewport) return delta

    var viewportPadding = this.options.viewport && this.options.viewport.padding || 0
    var viewportDimensions = this.getPosition(this.$viewport)

    if (/right|left/.test(placement)) {
      var topEdgeOffset    = pos.top - viewportPadding - viewportDimensions.scroll
      var bottomEdgeOffset = pos.top + viewportPadding - viewportDimensions.scroll + actualHeight
      if (topEdgeOffset < viewportDimensions.top) { // top overflow
        delta.top = viewportDimensions.top - topEdgeOffset
      } else if (bottomEdgeOffset > viewportDimensions.top + viewportDimensions.height) { // bottom overflow
        delta.top = viewportDimensions.top + viewportDimensions.height - bottomEdgeOffset
      }
    } else {
      var leftEdgeOffset  = pos.left - viewportPadding
      var rightEdgeOffset = pos.left + viewportPadding + actualWidth
      if (leftEdgeOffset < viewportDimensions.left) { // left overflow
        delta.left = viewportDimensions.left - leftEdgeOffset
      } else if (rightEdgeOffset > viewportDimensions.width) { // right overflow
        delta.left = viewportDimensions.left + viewportDimensions.width - rightEdgeOffset
      }
    }

    return delta
  }

  Tooltip.prototype.getTitle = function () {
    var title
    var $e = this.$element
    var o  = this.options

    title = $e.attr('data-original-title')
      || (typeof o.title == 'function' ? o.title.call($e[0]) :  o.title)

    return title
  }

  Tooltip.prototype.getUID = function (prefix) {
    do prefix += ~~(Math.random() * 1000000)
    while (document.getElementById(prefix))
    return prefix
  }

  Tooltip.prototype.tip = function () {
    return (this.$tip = this.$tip || $(this.options.template))
  }

  Tooltip.prototype.arrow = function () {
    return (this.$arrow = this.$arrow || this.tip().find('.tooltip-arrow'))
  }

  Tooltip.prototype.enable = function () {
    this.enabled = true
  }

  Tooltip.prototype.disable = function () {
    this.enabled = false
  }

  Tooltip.prototype.toggleEnabled = function () {
    this.enabled = !this.enabled
  }

  Tooltip.prototype.toggle = function (e) {
    var self = this
    if (e) {
      self = $(e.currentTarget).data('bs.' + this.type)
      if (!self) {
        self = new this.constructor(e.currentTarget, this.getDelegateOptions())
        $(e.currentTarget).data('bs.' + this.type, self)
      }
    }

    self.tip().hasClass('in') ? self.leave(self) : self.enter(self)
  }

  Tooltip.prototype.destroy = function () {
    var that = this
    clearTimeout(this.timeout)
    this.hide(function () {
      that.$element.off('.' + that.type).removeData('bs.' + that.type)
    })
  }


  // TOOLTIP PLUGIN DEFINITION
  // =========================

  function Plugin(option) {
    return this.each(function () {
      var $this   = $(this)
      var data    = $this.data('bs.tooltip')
      var options = typeof option == 'object' && option

      if (!data && /destroy|hide/.test(option)) return
      if (!data) $this.data('bs.tooltip', (data = new Tooltip(this, options)))
      if (typeof option == 'string') data[option]()
    })
  }

  var old = $.fn.tooltip

  $.fn.tooltip             = Plugin
  $.fn.tooltip.Constructor = Tooltip


  // TOOLTIP NO CONFLICT
  // ===================

  $.fn.tooltip.noConflict = function () {
    $.fn.tooltip = old
    return this
  }

}(jQuery);

/* ========================================================================
 * Bootstrap: popover.js v3.3.4
 * http://getbootstrap.com/javascript/#popovers
 * ========================================================================
 * Copyright 2011-2015 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 * ======================================================================== */


+function ($) {
  'use strict';

  // POPOVER PUBLIC CLASS DEFINITION
  // ===============================

  var Popover = function (element, options) {
    this.init('popover', element, options)
  }

  if (!$.fn.tooltip) throw new Error('Popover requires tooltip.js')

  Popover.VERSION  = '3.3.4'

  Popover.DEFAULTS = $.extend({}, $.fn.tooltip.Constructor.DEFAULTS, {
    placement: 'right',
    trigger: 'click',
    content: '',
    template: '<div class="popover" role="tooltip"><div class="arrow"></div><h3 class="popover-title"></h3><div class="popover-content"></div></div>'
  })


  // NOTE: POPOVER EXTENDS tooltip.js
  // ================================

  Popover.prototype = $.extend({}, $.fn.tooltip.Constructor.prototype)

  Popover.prototype.constructor = Popover

  Popover.prototype.getDefaults = function () {
    return Popover.DEFAULTS
  }

  Popover.prototype.setContent = function () {
    var $tip    = this.tip()
    var title   = this.getTitle()
    var content = this.getContent()

    $tip.find('.popover-title')[this.options.html ? 'html' : 'text'](title)
    $tip.find('.popover-content').children().detach().end()[ // we use append for html objects to maintain js events
      this.options.html ? (typeof content == 'string' ? 'html' : 'append') : 'text'
    ](content)

    $tip.removeClass('fade top bottom left right in')

    // IE8 doesn't accept hiding via the `:empty` pseudo selector, we have to do
    // this manually by checking the contents.
    if (!$tip.find('.popover-title').html()) $tip.find('.popover-title').hide()
  }

  Popover.prototype.hasContent = function () {
    return this.getTitle() || this.getContent()
  }

  Popover.prototype.getContent = function () {
    var $e = this.$element
    var o  = this.options

    return $e.attr('data-content')
      || (typeof o.content == 'function' ?
            o.content.call($e[0]) :
            o.content)
  }

  Popover.prototype.arrow = function () {
    return (this.$arrow = this.$arrow || this.tip().find('.arrow'))
  }


  // POPOVER PLUGIN DEFINITION
  // =========================

  function Plugin(option) {
    return this.each(function () {
      var $this   = $(this)
      var data    = $this.data('bs.popover')
      var options = typeof option == 'object' && option

      if (!data && /destroy|hide/.test(option)) return
      if (!data) $this.data('bs.popover', (data = new Popover(this, options)))
      if (typeof option == 'string') data[option]()
    })
  }

  var old = $.fn.popover

  $.fn.popover             = Plugin
  $.fn.popover.Constructor = Popover


  // POPOVER NO CONFLICT
  // ===================

  $.fn.popover.noConflict = function () {
    $.fn.popover = old
    return this
  }

}(jQuery);

/* ========================================================================
 * Bootstrap: scrollspy.js v3.3.4
 * http://getbootstrap.com/javascript/#scrollspy
 * ========================================================================
 * Copyright 2011-2015 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 * ======================================================================== */


+function ($) {
  'use strict';

  // SCROLLSPY CLASS DEFINITION
  // ==========================

  function ScrollSpy(element, options) {
    this.$body          = $(document.body)
    this.$scrollElement = $(element).is(document.body) ? $(window) : $(element)
    this.options        = $.extend({}, ScrollSpy.DEFAULTS, options)
    this.selector       = (this.options.target || '') + ' .nav li > a'
    this.offsets        = []
    this.targets        = []
    this.activeTarget   = null
    this.scrollHeight   = 0

    this.$scrollElement.on('scroll.bs.scrollspy', $.proxy(this.process, this))
    this.refresh()
    this.process()
  }

  ScrollSpy.VERSION  = '3.3.4'

  ScrollSpy.DEFAULTS = {
    offset: 10
  }

  ScrollSpy.prototype.getScrollHeight = function () {
    return this.$scrollElement[0].scrollHeight || Math.max(this.$body[0].scrollHeight, document.documentElement.scrollHeight)
  }

  ScrollSpy.prototype.refresh = function () {
    var that          = this
    var offsetMethod  = 'offset'
    var offsetBase    = 0

    this.offsets      = []
    this.targets      = []
    this.scrollHeight = this.getScrollHeight()

    if (!$.isWindow(this.$scrollElement[0])) {
      offsetMethod = 'position'
      offsetBase   = this.$scrollElement.scrollTop()
    }

    this.$body
      .find(this.selector)
      .map(function () {
        var $el   = $(this)
        var href  = $el.data('target') || $el.attr('href')
        var $href = /^#./.test(href) && $(href)

        return ($href
          && $href.length
          && $href.is(':visible')
          && [[$href[offsetMethod]().top + offsetBase, href]]) || null
      })
      .sort(function (a, b) { return a[0] - b[0] })
      .each(function () {
        that.offsets.push(this[0])
        that.targets.push(this[1])
      })
  }

  ScrollSpy.prototype.process = function () {
    var scrollTop    = this.$scrollElement.scrollTop() + this.options.offset
    var scrollHeight = this.getScrollHeight()
    var maxScroll    = this.options.offset + scrollHeight - this.$scrollElement.height()
    var offsets      = this.offsets
    var targets      = this.targets
    var activeTarget = this.activeTarget
    var i

    if (this.scrollHeight != scrollHeight) {
      this.refresh()
    }

    if (scrollTop >= maxScroll) {
      return activeTarget != (i = targets[targets.length - 1]) && this.activate(i)
    }

    if (activeTarget && scrollTop < offsets[0]) {
      this.activeTarget = null
      return this.clear()
    }

    for (i = offsets.length; i--;) {
      activeTarget != targets[i]
        && scrollTop >= offsets[i]
        && (offsets[i + 1] === undefined || scrollTop < offsets[i + 1])
        && this.activate(targets[i])
    }
  }

  ScrollSpy.prototype.activate = function (target) {
    this.activeTarget = target

    this.clear()

    var selector = this.selector +
      '[data-target="' + target + '"],' +
      this.selector + '[href="' + target + '"]'

    var active = $(selector)
      .parents('li')
      .addClass('active')

    if (active.parent('.dropdown-menu').length) {
      active = active
        .closest('li.dropdown')
        .addClass('active')
    }

    active.trigger('activate.bs.scrollspy')
  }

  ScrollSpy.prototype.clear = function () {
    $(this.selector)
      .parentsUntil(this.options.target, '.active')
      .removeClass('active')
  }


  // SCROLLSPY PLUGIN DEFINITION
  // ===========================

  function Plugin(option) {
    return this.each(function () {
      var $this   = $(this)
      var data    = $this.data('bs.scrollspy')
      var options = typeof option == 'object' && option

      if (!data) $this.data('bs.scrollspy', (data = new ScrollSpy(this, options)))
      if (typeof option == 'string') data[option]()
    })
  }

  var old = $.fn.scrollspy

  $.fn.scrollspy             = Plugin
  $.fn.scrollspy.Constructor = ScrollSpy


  // SCROLLSPY NO CONFLICT
  // =====================

  $.fn.scrollspy.noConflict = function () {
    $.fn.scrollspy = old
    return this
  }


  // SCROLLSPY DATA-API
  // ==================

  $(window).on('load.bs.scrollspy.data-api', function () {
    $('[data-spy="scroll"]').each(function () {
      var $spy = $(this)
      Plugin.call($spy, $spy.data())
    })
  })

}(jQuery);

/* ========================================================================
 * Bootstrap: tab.js v3.3.4
 * http://getbootstrap.com/javascript/#tabs
 * ========================================================================
 * Copyright 2011-2015 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 * ======================================================================== */


+function ($) {
  'use strict';

  // TAB CLASS DEFINITION
  // ====================

  var Tab = function (element) {
    this.element = $(element)
  }

  Tab.VERSION = '3.3.4'

  Tab.TRANSITION_DURATION = 150

  Tab.prototype.show = function () {
    var $this    = this.element
    var $ul      = $this.closest('ul:not(.dropdown-menu)')
    var selector = $this.data('target')

    if (!selector) {
      selector = $this.attr('href')
      selector = selector && selector.replace(/.*(?=#[^\s]*$)/, '') // strip for ie7
    }

    if ($this.parent('li').hasClass('active')) return

    var $previous = $ul.find('.active:last a')
    var hideEvent = $.Event('hide.bs.tab', {
      relatedTarget: $this[0]
    })
    var showEvent = $.Event('show.bs.tab', {
      relatedTarget: $previous[0]
    })

    $previous.trigger(hideEvent)
    $this.trigger(showEvent)

    if (showEvent.isDefaultPrevented() || hideEvent.isDefaultPrevented()) return

    var $target = $(selector)

    this.activate($this.closest('li'), $ul)
    this.activate($target, $target.parent(), function () {
      $previous.trigger({
        type: 'hidden.bs.tab',
        relatedTarget: $this[0]
      })
      $this.trigger({
        type: 'shown.bs.tab',
        relatedTarget: $previous[0]
      })
    })
  }

  Tab.prototype.activate = function (element, container, callback) {
    var $active    = container.find('> .active')
    var transition = callback
      && $.support.transition
      && (($active.length && $active.hasClass('fade')) || !!container.find('> .fade').length)

    function next() {
      $active
        .removeClass('active')
        .find('> .dropdown-menu > .active')
          .removeClass('active')
        .end()
        .find('[data-toggle="tab"]')
          .attr('aria-expanded', false)

      element
        .addClass('active')
        .find('[data-toggle="tab"]')
          .attr('aria-expanded', true)

      if (transition) {
        element[0].offsetWidth // reflow for transition
        element.addClass('in')
      } else {
        element.removeClass('fade')
      }

      if (element.parent('.dropdown-menu').length) {
        element
          .closest('li.dropdown')
            .addClass('active')
          .end()
          .find('[data-toggle="tab"]')
            .attr('aria-expanded', true)
      }

      callback && callback()
    }

    $active.length && transition ?
      $active
        .one('bsTransitionEnd', next)
        .emulateTransitionEnd(Tab.TRANSITION_DURATION) :
      next()

    $active.removeClass('in')
  }


  // TAB PLUGIN DEFINITION
  // =====================

  function Plugin(option) {
    return this.each(function () {
      var $this = $(this)
      var data  = $this.data('bs.tab')

      if (!data) $this.data('bs.tab', (data = new Tab(this)))
      if (typeof option == 'string') data[option]()
    })
  }

  var old = $.fn.tab

  $.fn.tab             = Plugin
  $.fn.tab.Constructor = Tab


  // TAB NO CONFLICT
  // ===============

  $.fn.tab.noConflict = function () {
    $.fn.tab = old
    return this
  }


  // TAB DATA-API
  // ============

  var clickHandler = function (e) {
    e.preventDefault()
    Plugin.call($(this), 'show')
  }

  $(document)
    .on('click.bs.tab.data-api', '[data-toggle="tab"]', clickHandler)
    .on('click.bs.tab.data-api', '[data-toggle="pill"]', clickHandler)

}(jQuery);

/* ========================================================================
 * Bootstrap: affix.js v3.3.4
 * http://getbootstrap.com/javascript/#affix
 * ========================================================================
 * Copyright 2011-2015 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 * ======================================================================== */


+function ($) {
  'use strict';

  // AFFIX CLASS DEFINITION
  // ======================

  var Affix = function (element, options) {
    this.options = $.extend({}, Affix.DEFAULTS, options)

    this.$target = $(this.options.target)
      .on('scroll.bs.affix.data-api', $.proxy(this.checkPosition, this))
      .on('click.bs.affix.data-api',  $.proxy(this.checkPositionWithEventLoop, this))

    this.$element     = $(element)
    this.affixed      = null
    this.unpin        = null
    this.pinnedOffset = null

    this.checkPosition()
  }

  Affix.VERSION  = '3.3.4'

  Affix.RESET    = 'affix affix-top affix-bottom'

  Affix.DEFAULTS = {
    offset: 0,
    target: window
  }

  Affix.prototype.getState = function (scrollHeight, height, offsetTop, offsetBottom) {
    var scrollTop    = this.$target.scrollTop()
    var position     = this.$element.offset()
    var targetHeight = this.$target.height()

    if (offsetTop != null && this.affixed == 'top') return scrollTop < offsetTop ? 'top' : false

    if (this.affixed == 'bottom') {
      if (offsetTop != null) return (scrollTop + this.unpin <= position.top) ? false : 'bottom'
      return (scrollTop + targetHeight <= scrollHeight - offsetBottom) ? false : 'bottom'
    }

    var initializing   = this.affixed == null
    var colliderTop    = initializing ? scrollTop : position.top
    var colliderHeight = initializing ? targetHeight : height

    if (offsetTop != null && scrollTop <= offsetTop) return 'top'
    if (offsetBottom != null && (colliderTop + colliderHeight >= scrollHeight - offsetBottom)) return 'bottom'

    return false
  }

  Affix.prototype.getPinnedOffset = function () {
    if (this.pinnedOffset) return this.pinnedOffset
    this.$element.removeClass(Affix.RESET).addClass('affix')
    var scrollTop = this.$target.scrollTop()
    var position  = this.$element.offset()
    return (this.pinnedOffset = position.top - scrollTop)
  }

  Affix.prototype.checkPositionWithEventLoop = function () {
    setTimeout($.proxy(this.checkPosition, this), 1)
  }

  Affix.prototype.checkPosition = function () {
    if (!this.$element.is(':visible')) return

    var height       = this.$element.height()
    var offset       = this.options.offset
    var offsetTop    = offset.top
    var offsetBottom = offset.bottom
    var scrollHeight = $(document.body).height()

    if (typeof offset != 'object')         offsetBottom = offsetTop = offset
    if (typeof offsetTop == 'function')    offsetTop    = offset.top(this.$element)
    if (typeof offsetBottom == 'function') offsetBottom = offset.bottom(this.$element)

    var affix = this.getState(scrollHeight, height, offsetTop, offsetBottom)

    if (this.affixed != affix) {
      if (this.unpin != null) this.$element.css('top', '')

      var affixType = 'affix' + (affix ? '-' + affix : '')
      var e         = $.Event(affixType + '.bs.affix')

      this.$element.trigger(e)

      if (e.isDefaultPrevented()) return

      this.affixed = affix
      this.unpin = affix == 'bottom' ? this.getPinnedOffset() : null

      this.$element
        .removeClass(Affix.RESET)
        .addClass(affixType)
        .trigger(affixType.replace('affix', 'affixed') + '.bs.affix')
    }

    if (affix == 'bottom') {
      this.$element.offset({
        top: scrollHeight - height - offsetBottom
      })
    }
  }


  // AFFIX PLUGIN DEFINITION
  // =======================

  function Plugin(option) {
    return this.each(function () {
      var $this   = $(this)
      var data    = $this.data('bs.affix')
      var options = typeof option == 'object' && option

      if (!data) $this.data('bs.affix', (data = new Affix(this, options)))
      if (typeof option == 'string') data[option]()
    })
  }

  var old = $.fn.affix

  $.fn.affix             = Plugin
  $.fn.affix.Constructor = Affix


  // AFFIX NO CONFLICT
  // =================

  $.fn.affix.noConflict = function () {
    $.fn.affix = old
    return this
  }


  // AFFIX DATA-API
  // ==============

  $(window).on('load', function () {
    $('[data-spy="affix"]').each(function () {
      var $spy = $(this)
      var data = $spy.data()

      data.offset = data.offset || {}

      if (data.offsetBottom != null) data.offset.bottom = data.offsetBottom
      if (data.offsetTop    != null) data.offset.top    = data.offsetTop

      Plugin.call($spy, data)
    })
  })

}(jQuery);

// secrets.js - by Alexander Stetsyuk - released under MIT License
(function(exports, global){
var defaults = {
	bits: 8, // default number of bits
	radix: 16, // work with HEX by default
	minBits: 3,
	maxBits: 20, // this permits 1,048,575 shares, though going this high is NOT recommended in JS!
	
	bytesPerChar: 2,
	maxBytesPerChar: 6, // Math.pow(256,7) > Math.pow(2,53)
		
	// Primitive polynomials (in decimal form) for Galois Fields GF(2^n), for 2 <= n <= 30
	// The index of each term in the array corresponds to the n for that polynomial
	// i.e. to get the polynomial for n=16, use primitivePolynomials[16]
	primitivePolynomials: [null,null,1,3,3,5,3,3,29,17,9,5,83,27,43,3,45,9,39,39,9,5,3,33,27,9,71,39,9,5,83],
	
	// warning for insecure PRNG
	warning: 'WARNING:\nA secure random number generator was not found.\nUsing Math.random(), which is NOT cryptographically strong!'
};

// Protected settings object
var config = {};

/** @expose **/
exports.getConfig = function(){
	return {
		'bits': config.bits,
		'unsafePRNG': config.unsafePRNG
	};
};

function init(bits){
	if(bits && (typeof bits !== 'number' || bits%1 !== 0 || bits<defaults.minBits || bits>defaults.maxBits)){
		throw new Error('Number of bits must be an integer between ' + defaults.minBits + ' and ' + defaults.maxBits + ', inclusive.')
	}
	
	config.radix = defaults.radix;
	config.bits = bits || defaults.bits;
	config.size = Math.pow(2, config.bits);
	config.max = config.size - 1;
	
	// Construct the exp and log tables for multiplication.	
	var logs = [], exps = [], x = 1, primitive = defaults.primitivePolynomials[config.bits];
	for(var i=0; i<config.size; i++){
		exps[i] = x;
		logs[x] = i;
		x <<= 1;
		if(x >= config.size){
			x ^= primitive;
			x &= config.max;
		}
	}
		
	config.logs = logs;
	config.exps = exps;
};

/** @expose **/
exports.init = init;

function isInited(){
	if(!config.bits || !config.size || !config.max  || !config.logs || !config.exps || config.logs.length !== config.size || config.exps.length !== config.size){
		return false;
	}
	return true;
};

// Returns a pseudo-random number generator of the form function(bits){}
// which should output a random string of 1's and 0's of length `bits`
function getRNG(){
	var randomBits, crypto;
	
	function construct(bits, arr, radix, size){
		var str = '',
			i = 0,
			len = arr.length-1;
		while( i<len || (str.length < bits) ){
			str += padLeft(parseInt(arr[i], radix).toString(2), size);
			i++;
		}
		str = str.substr(-bits);
		if( (str.match(/0/g)||[]).length === str.length){ // all zeros?
			return null;
		}else{
			return str;
		}
	}
	
	// node.js crypto.randomBytes()
	if(typeof require === 'function' && (crypto=require('crypto')) && (randomBits=crypto['randomBytes'])){
		return function(bits){
			var bytes = Math.ceil(bits/8),
				str = null;
		
			while( str === null ){
				str = construct(bits, randomBits(bytes).toString('hex'), 16, 4);
			}
			return str;
		}
	}
	
	// browsers with window.crypto.getRandomValues()
	if(global['crypto'] && typeof global['crypto']['getRandomValues'] === 'function' && typeof global['Uint32Array'] === 'function'){
		crypto = global['crypto'];
		return function(bits){
			var elems = Math.ceil(bits/32),
				str = null,
				arr = new global['Uint32Array'](elems);

			while( str === null ){
				crypto['getRandomValues'](arr);
				str = construct(bits, arr, 10, 32);
			}
			
			return str;	
		}
	}

	// A totally insecure RNG!!! (except in Safari)
	// Will produce a warning every time it is called.
	config.unsafePRNG = true;
	warn();
	
	var bitsPerNum = 32;
	var max = Math.pow(2,bitsPerNum)-1;
	return function(bits){
		var elems = Math.ceil(bits/bitsPerNum);
		var arr = [], str=null;
		while(str===null){
			for(var i=0; i<elems; i++){
				arr[i] = Math.floor(Math.random() * max + 1); 
			}
			str = construct(bits, arr, 10, bitsPerNum);
		}
		return str;
	};
};

// Warn about using insecure rng.
// Called when Math.random() is being used.
function warn(){
	global['console']['warn'](defaults.warning);
	if(typeof global['alert'] === 'function' && config.alert){
		global['alert'](defaults.warning);
	}
}

// Set the PRNG to use. If no RNG function is supplied, pick a default using getRNG()
/** @expose **/
exports.setRNG = function(rng, alert){
	if(!isInited()){
		this.init();
	}
	config.unsafePRNG=false;
	rng = rng || getRNG();
	
	// test the RNG (5 times)
	if(typeof rng !== 'function' || typeof rng(config.bits) !== 'string' || !parseInt(rng(config.bits),2) || rng(config.bits).length > config.bits || rng(config.bits).length < config.bits){
		throw new Error("Random number generator is invalid. Supply an RNG of the form function(bits){} that returns a string containing 'bits' number of random 1's and 0's.")
	}else{
		config.rng = rng;
	}
	config.alert = !!alert;
	
	return !!config.unsafePRNG;
};

function isSetRNG(){
	return typeof config.rng === 'function'; 
};

// Generates a random bits-length number string using the PRNG
/** @expose **/
exports.random = function(bits){
	if(!isSetRNG()){
		this.setRNG();
	}
	
	if(typeof bits !== 'number' || bits%1 !== 0 || bits < 2){
		throw new Error('Number of bits must be an integer greater than 1.')
	}
	
	if(config.unsafePRNG){
		warn();
	}
	return bin2hex(config.rng(bits));
}

// Divides a `secret` number String str expressed in radix `inputRadix` (optional, default 16) 
// into `numShares` shares, each expressed in radix `outputRadix` (optional, default to `inputRadix`), 
// requiring `threshold` number of shares to reconstruct the secret. 
// Optionally, zero-pads the secret to a length that is a multiple of padLength before sharing.
/** @expose **/
exports.share = function(secret, numShares, threshold, padLength, withoutPrefix){
	if(!isInited()){
		this.init();
	}
	if(!isSetRNG()){
		this.setRNG();
	}
	
	padLength =  padLength || 0;
		
	if(typeof secret !== 'string'){
		throw new Error('Secret must be a string.');
	}
	if(typeof numShares !== 'number' || numShares%1 !== 0 || numShares < 2){
		throw new Error('Number of shares must be an integer between 2 and 2^bits-1 (' + config.max + '), inclusive.')
	}
	if(numShares > config.max){
		var neededBits = Math.ceil(Math.log(numShares +1)/Math.LN2);
		throw new Error('Number of shares must be an integer between 2 and 2^bits-1 (' + config.max + '), inclusive. To create ' + numShares + ' shares, use at least ' + neededBits + ' bits.')	
	}
	if(typeof threshold !== 'number' || threshold%1 !== 0 || threshold < 2){
		throw new Error('Threshold number of shares must be an integer between 2 and 2^bits-1 (' + config.max + '), inclusive.');
	}
	if(threshold > config.max){
		var neededBits = Math.ceil(Math.log(threshold +1)/Math.LN2);
		throw new Error('Threshold number of shares must be an integer between 2 and 2^bits-1 (' + config.max + '), inclusive.  To use a threshold of ' + threshold + ', use at least ' + neededBits + ' bits.');
	}
	if(typeof padLength !== 'number' || padLength%1 !== 0 ){
		throw new Error('Zero-pad length must be an integer greater than 1.');
	}
	
	if(config.unsafePRNG){
		warn();
	}
	
	secret = '1' + hex2bin(secret); // append a 1 so that we can preserve the correct number of leading zeros in our secret
	secret = split(secret, padLength);	
	var x = new Array(numShares), y = new Array(numShares);
	for(var i=0, len = secret.length; i<len; i++){
		var subShares = this._getShares(secret[i], numShares, threshold);
		for(var j=0; j<numShares; j++){
			x[j] = x[j] || subShares[j].x.toString(config.radix);
			y[j] = padLeft(subShares[j].y.toString(2)) + (y[j] ? y[j] : '');
		}
	}
	var padding = config.max.toString(config.radix).length;
	if(withoutPrefix){
		for(var i=0; i<numShares; i++){
			x[i] = bin2hex(y[i]);
		}
	}else{
		for(var i=0; i<numShares; i++){
			x[i] = config.bits.toString(36).toUpperCase() + padLeft(x[i],padding) + bin2hex(y[i]);
		}
	}
	
	return x;
};

// This is the basic polynomial generation and evaluation function 
// for a `config.bits`-length secret (NOT an arbitrary length)
// Note: no error-checking at this stage! If `secrets` is NOT 
// a NUMBER less than 2^bits-1, the output will be incorrect!
/** @expose **/
exports._getShares = function(secret, numShares, threshold){	
	var shares = [];
	var coeffs = [secret]; 
		
	for(var i=1; i<threshold; i++){
		coeffs[i] = parseInt(config.rng(config.bits),2);
	}
	for(var i=1, len = numShares+1; i<len; i++){
		shares[i-1] = {
			x: i,
			y: horner(i, coeffs)
		}
	}
	return shares;
};
	
// Polynomial evaluation at `x` using Horner's Method
// TODO: this can possibly be sped up using other methods
// NOTE: fx=fx * x + coeff[i] ->  exp(log(fx) + log(x)) + coeff[i], 
//       so if fx===0, just set fx to coeff[i] because
//       using the exp/log form will result in incorrect value
function horner(x, coeffs){
	var logx = config.logs[x];
	var fx = 0;
	for(var i=coeffs.length-1; i>=0; i--){	
		if(fx === 0){
			fx = coeffs[i];
			continue;
		}
		fx = config.exps[ (logx + config.logs[fx]) % config.max ] ^ coeffs[i];
	}
	return fx;
};

function inArray(arr,val){
	for(var i = 0,len=arr.length; i < len; i++) {
		if(arr[i] === val){
   		 return true;
	 	}
 	}
	return false;
};

function processShare(share){
	
	var bits = parseInt(share[0], 36);
	if(bits && (typeof bits !== 'number' || bits%1 !== 0 || bits<defaults.minBits || bits>defaults.maxBits)){
		throw new Error('Number of bits must be an integer between ' + defaults.minBits + ' and ' + defaults.maxBits + ', inclusive.')
	}
	
	var max = Math.pow(2, bits) - 1;
	var idLength = max.toString(config.radix).length;
	
	var id = parseInt(share.substr(1, idLength), config.radix);
	if(typeof id !== 'number' || id%1 !== 0 || id<1 || id>max){
		throw new Error('Share id must be an integer between 1 and ' + config.max + ', inclusive.');
	}
	share = share.substr(idLength + 1);
	if(!share.length){
		throw new Error('Invalid share: zero-length share.')
	}
	return {
		'bits': bits,
		'id': id,
		'value': share
	};
};

/** @expose **/
exports._processShare = processShare;

// Protected method that evaluates the Lagrange interpolation
// polynomial at x=`at` for individual config.bits-length
// segments of each share in the `shares` Array.
// Each share is expressed in base `inputRadix`. The output 
// is expressed in base `outputRadix'
function combine(at, shares){
	var setBits, share, x = [], y = [], result = '', idx;	
	
	for(var i=0, len = shares.length; i<len; i++){
		share = processShare(shares[i]);
		if(typeof setBits === 'undefined'){
			setBits = share['bits'];
		}else if(share['bits'] !== setBits){
			throw new Error('Mismatched shares: Different bit settings.')
		}
		
		if(config.bits !== setBits){
			init(setBits);
		}
		
		if(inArray(x, share['id'])){ // repeated x value?
			continue;
		}
	
		idx = x.push(share['id']) - 1;
		share = split(hex2bin(share['value']));
		for(var j=0, len2 = share.length; j<len2; j++){
			y[j] = y[j] || [];
			y[j][idx] = share[j];
		}
	}
	
	for(var i=0, len=y.length; i<len; i++){
		result = padLeft(lagrange(at, x, y[i]).toString(2)) + result;
	}

	if(at===0){// reconstructing the secret
		var idx = result.indexOf('1'); //find the first 1
		return bin2hex(result.slice(idx+1));
	}else{// generating a new share
		return bin2hex(result);
	}
};

// Combine `shares` Array into the original secret
/** @expose **/
exports.combine = function(shares){
	return combine(0, shares);
};

// Generate a new share with id `id` (a number between 1 and 2^bits-1)
// `id` can be a Number or a String in the default radix (16)
/** @expose **/
exports.newShare = function(id, shares){
	if(typeof id === 'string'){
		id = parseInt(id, config.radix);	
	}
	
	var share = processShare(shares[0]);
	var max = Math.pow(2, share['bits']) - 1;
	
	if(typeof id !== 'number' || id%1 !== 0 || id<1 || id>max){
		throw new Error('Share id must be an integer between 1 and ' + config.max + ', inclusive.');
	}

	var padding = max.toString(config.radix).length;
	return config.bits.toString(36).toUpperCase() + padLeft(id.toString(config.radix), padding) + combine(id, shares);
};
	
// Evaluate the Lagrange interpolation polynomial at x = `at`
// using x and y Arrays that are of the same length, with
// corresponding elements constituting points on the polynomial.
function lagrange(at, x, y){
	var sum = 0,
		product, 
		i, j;
		
	for(var i=0, len = x.length; i<len; i++){
		if(!y[i]){
			continue; 
		}
			
		product = config.logs[y[i]];
		for(var j=0; j<len; j++){
			if(i === j){ continue; }
			if(at === x[j]){ // happens when computing a share that is in the list of shares used to compute it
				product = -1; // fix for a zero product term, after which the sum should be sum^0 = sum, not sum^1
				break; 
			}
			product = ( product + config.logs[at ^ x[j]] - config.logs[x[i] ^ x[j]] + config.max/* to make sure it's not negative */ ) % config.max;
		}
			
		sum = product === -1 ? sum : sum ^ config.exps[product]; // though exps[-1]= undefined and undefined ^ anything = anything in chrome, this behavior may not hold everywhere, so do the check
	}
	return sum;
};

/** @expose **/
exports._lagrange = lagrange;

// Splits a number string `bits`-length segments, after first 
// optionally zero-padding it to a length that is a multiple of `padLength.
// Returns array of integers (each less than 2^bits-1), with each element
// representing a `bits`-length segment of the input string from right to left, 
// i.e. parts[0] represents the right-most `bits`-length segment of the input string.
function split(str, padLength){
	if(padLength){
		str = padLeft(str, padLength)
	}
	var parts = [];
	for(var i=str.length; i>config.bits; i-=config.bits){
		parts.push(parseInt(str.slice(i-config.bits, i), 2));
	}	
	parts.push(parseInt(str.slice(0, i), 2));	
	return parts;
};
	
// Pads a string `str` with zeros on the left so that its length is a multiple of `bits`
function padLeft(str, bits){
	bits = bits || config.bits
	var missing = str.length % bits;
	return (missing ? new Array(bits - missing + 1).join('0') : '') + str;
};

function hex2bin(str){
	var bin = '', num;
	for(var i=str.length - 1; i>=0; i--){
		num = parseInt(str[i], 16)
		if(isNaN(num)){
			throw new Error('Invalid hex character.')
		}
		bin = padLeft(num.toString(2), 4) + bin;
	}
	return bin;
}

function bin2hex(str){
	var hex = '', num;
	str = padLeft(str, 4);
	for(var i=str.length; i>=4; i-=4){
		num = parseInt(str.slice(i-4, i), 2);
		if(isNaN(num)){
			throw new Error('Invalid binary character.')
		}
		hex = num.toString(16) + hex;
	}
	return hex;
}
	
// Converts a given UTF16 character string to the HEX representation. 
// Each character of the input string is represented by 
// `bytesPerChar` bytes in the output string.
/** @expose **/
exports.str2hex = function(str, bytesPerChar){
	if(typeof str !== 'string'){
		throw new Error('Input must be a character string.');
	}
	bytesPerChar = bytesPerChar || defaults.bytesPerChar;
	
	if(typeof bytesPerChar !== 'number' || bytesPerChar%1 !== 0 || bytesPerChar<1 || bytesPerChar > defaults.maxBytesPerChar){
		throw new Error('Bytes per character must be an integer between 1 and ' + defaults.maxBytesPerChar + ', inclusive.')
	}
	
	var hexChars = 2*bytesPerChar;
	var max = Math.pow(16, hexChars) - 1;
	var out = '', num;
	for(var i=0, len=str.length; i<len; i++){
		num = str[i].charCodeAt();
		if(isNaN(num)){
			throw new Error('Invalid character: ' + str[i]);
		}else if(num > max){
			var neededBytes = Math.ceil(Math.log(num+1)/Math.log(256));
			throw new Error('Invalid character code (' + num +'). Maximum allowable is 256^bytes-1 (' + max + '). To convert this character, use at least ' + neededBytes + ' bytes.')
		}else{
			out = padLeft(num.toString(16), hexChars) + out;
		}
	}
	return out;
};
	
// Converts a given HEX number string to a UTF16 character string. 
/** @expose **/
exports.hex2str = function(str, bytesPerChar){
	if(typeof str !== 'string'){
		throw new Error('Input must be a hexadecimal string.');
	}
	bytesPerChar = bytesPerChar || defaults.bytesPerChar;
	
	if(typeof bytesPerChar !== 'number' || bytesPerChar%1 !== 0 || bytesPerChar<1 || bytesPerChar > defaults.maxBytesPerChar){
		throw new Error('Bytes per character must be an integer between 1 and ' + defaults.maxBytesPerChar + ', inclusive.')
	}
	
	var hexChars = 2*bytesPerChar;
	var out = '';
	str = padLeft(str, hexChars);
	for(var i=0, len = str.length; i<len; i+=hexChars){
		out = String.fromCharCode(parseInt(str.slice(i, i+hexChars),16)) + out;
	}
	return out;
};
	
// by default, initialize without an RNG
exports.init();
})(typeof module !== 'undefined' && module['exports'] ? module['exports'] : (window['secrets'] = {}), typeof GLOBAL !== 'undefined' ? GLOBAL : window );