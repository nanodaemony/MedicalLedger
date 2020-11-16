#!/usr/bin/env bash
#
# simple batch script making it easier to cleanup and start a relatively fresh fabric env.

# docker-compose.yaml文件不存在(将docker-compose.yaml放到当前文件夹下)
if [ ! -e "docker-compose.yaml" ];then
  echo "docker-compose.yaml not found."
  exit 8
fi

ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION=${ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION:-}

# 清理函数
function clean(){
  # 删除文件夹下全部内容
  rm -rf /var/hyperledger/*

  # 删除临时文件
  if [ -e "/tmp/HFCSampletest.properties" ];then
    rm -f "/tmp/HFCSampletest.properties"
  fi
  lines=`docker ps -a | grep 'dev-peer' | wc -l`

  if [ "$lines" -gt 0 ]; then
    docker ps -a | grep 'dev-peer' | awk '{print $1}' | xargs docker rm -f
  fi

  lines=`docker images | grep 'dev-peer' | grep 'dev-peer' | wc -l`
  if [ "$lines" -gt 0 ]; then
    docker images | grep 'dev-peer' | awk '{print $1}' | xargs docker rmi -f
  fi
}

# 启动函数
function up(){

  if [ "$ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION" == "1.0.0" ]; then
    docker-compose up --force-recreate ca0 ca1 peer1.org1.example.com peer1.org2.example.com
    # 非1.0版本启动这个
  else
    docker-compose up --force-recreate
fi

}

function down(){
  docker-compose down;
}

function stop (){
  docker-compose stop;
}

function start (){
  docker-compose start;
}


for opt in "$@"
do

    case "$opt" in
        up)
            up
            ;;
        down)
            down
            ;;
        stop)
            stop
            ;;
        start)
            start
            ;;
        clean)
            clean
            ;;
        restart)
            down
            clean
            up
            ;;
        *)
            echo $"Help, Please Input the arg: $0 {up|down|start|stop|clean|restart}"
            exit 1

esac
done
