#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

function abort {
	set +x

	echo "------------------------------------------------------------------------"
	echo "                          K8s Test Failed"
	echo "$*"
	echo ""
	echo "------------------------------------------------------------------------"

	cilium_id=$(docker ps -aq --filter=name=cilium-agent)
	echo "------------------------------------------------------------------------"
	echo "                            Cilium logs"
	docker logs ${cilium_id}
	echo ""
	echo "------------------------------------------------------------------------"

    echo "------------------------------------------------------------------------"
    echo "                            L7 Proxy logs"
    cat /var/lib/cilium/proxy.log
	echo ""
	echo "------------------------------------------------------------------------"

	exit 1
}

function gather_k8s_logs {
  local LOCAL_NODE_NUM=$1
  local LOGS_DIR=$2

  mkdir -p ${LOGS_DIR}
  local CILIUM_PODS=$(kubectl get pods -n ${NAMESPACE} -l k8s-app=cilium | tail -n +2 | awk '{print $1}')
  for pod in $CILIUM_PODS; do 
    local NODE_NAME=$(kubectl get pod -n ${NAMESPACE} $pod  -o wide | tail -n +2 | awk '{print $7}')
    kubectl logs -n ${NAMESPACE} ${pod} > ${LOGS_DIR}/${pod}-${NODE_NAME}-logs || true
  done
  kubectl logs -n kube-system kube-apiserver-k8s-1 > ${LOGS_DIR}/kube-apiserver-k8s-1-logs || true
  kubectl logs -n kube-system kube-controller-manager-k8s-1 > ${LOGS_DIR}/kube-controller-manager-k8s-1-logs || true
  journalctl -au kubelet > ${LOGS_DIR}/kubelet-k8s-${LOCAL_NODE_NUM}-logs || true
}
