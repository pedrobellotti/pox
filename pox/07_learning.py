# Copyright 2011-2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
import time

log = core.getLogger()
sHW = None
sSW = None
sUL = None
sDL = None

class LearningSwitch (object):

  #Inicializa o switch
  def __init__ (self, connection, nome):
    # Conexao com o switch
    self.connection = connection
    # Tabela MAC->Porta
    self.macToPort = {}
    # Listeners para packetIn
    connection.addListeners(self)
    # Nome do switch
    self.nome = nome

  #Adiciona uma regra no switch
  def addRegra (self, regra):
    self.connection.send(regra)
    log.info ('%s: Regra adicionada' % (self.nome))
    #print regra

  #Packet In
  def _handle_PacketIn (self, event):
    packet = event.parsed #"Abre" o pacote
    #Somente os switches DL e UL possem aprendizado de portas
    if (self.nome == 'Switch DL' or self.nome == 'Switch UL'):
      if (event.port == 2):
        self.macToPort[packet.src] = event.port #Adiciona na tabela a porta para o mac
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        #Informacoes do pacote e da regra
        #dltype = msg.match.dl_type
        #inport = msg.match.in_port
        #dlsrc = msg.match.dl_src
        #dldst = msg.match.dl_dst
        #nwsrc = msg.match.nw_src
        #nwdst = msg.match.nw_dst
        #msg.idle_timeout = 500
        #msg.hard_timeout = 600
        protocolo = 'Nao identificado'
        if packet.find('tcp'):
          protocolo = 'TCP'
        elif packet.find('udp'):
          protocolo = 'UDP'
        elif packet.find('arp'):
          protocolo = 'ARP'
        elif packet.find('icmp'):
          protocolo = 'ICMP'
        #Informacoes de portas TCP/UDP
        protosrc = 0
        protodst = 0
        if (protocolo == 'UDP' or protocolo == 'TCP'):
          if (msg.match.tp_src is not None and msg.match.tp_dst is not None):
            protosrc = msg.match.tp_src
            protodst = msg.match.tp_dst

        #Logica de divisao de trafego
        if (self.nome == 'Switch DL'):
          # !!! Numero das portas nas regras podem mudar caso os cabos troquem de lugar !!!
          #Se chegou no switch DL e a porta do protocolo e PAR, encaminha para o switch HW:
          # 1) Adiciona regra 2->4 no switch DL
          # 2) Adiciona regra 2->3 no switch HW
          #Se chegou no switch DL e a porta e IMPAR, encaminha para o switch SW:
          # 1) Adiciona regra 3->2 no switch DL
          # 2) Adiciona regra 2->1 no switch SW
          if (protosrc != 0 and protodst != 0):
            if(protodst % 2 == 0):
              log.info("%s: Porta de protocolo PAR, encaminhando para switch HW." % (self.nome))
              #Porta de saida para o switch HW
              port = 4
              global sHW
              msgh = of.ofp_flow_mod()
              msgh.match = of.ofp_match.from_packet(packet, event.port)
              msgh.match.in_port = 2
              msgh.actions.append(of.ofp_action_output(port = 3))
              sHW.addRegra(msgh)
            else:
              log.info("%s: Porta de protocolo IMPAR, encaminhando para switch SW." % (self.nome))
              #Porta de saida para o switch SW
              port = 3
              global sSW
              msgs = of.ofp_flow_mod()
              msgs.match = of.ofp_match.from_packet(packet, event.port)
              msgs.match.in_port = 2
              msgs.actions.append(of.ofp_action_output(port = 1))
              sSW.addRegra(msgs)
          #Caso nao tenha porta de protocolo, o pacote nao e TCP nem UDP entao encaminha para o SW
          else:
            log.info("%s: Trafego diferente de TCP/UDP, encaminhando para switch SW." % (self.nome))
            #Porta de saida para o switch SW
            port = 3
            global sSW
            msgs = of.ofp_flow_mod()
            msgs.match = of.ofp_match.from_packet(packet, event.port)
            msgs.match.in_port = 2
            msgs.actions.append(of.ofp_action_output(port = 1))
            sSW.addRegra(msgs)

        elif (self.nome == 'Switch UL'):
          # !!! Numero das portas nas regras podem mudar caso os cabos troquem de lugar !!!
          #Se chegou no switch UL e a porta do protocolo e PAR, encaminha para o switch HW:
          # 1) Adiciona regra 2->1 no switch UL
          # 2) Adiciona regra 3->2 no switch HW
          #Se chegou no switch UL e a porta e IMPAR, encaminha para o switch SW:
          # 1) Adiciona regra 2->3 no switch UL
          # 2) Adiciona regra 1->2 no switch SW
          if (protosrc != 0 and protodst != 0):
            if(protodst % 2 == 0):
              log.info("%s: Porta de protocolo PAR, encaminhando para switch HW." % (self.nome))
              #Porta de saida para o switch HW
              port = 1
              global sHW
              msgh = of.ofp_flow_mod()
              msgh.match = of.ofp_match.from_packet(packet, event.port)
              msgh.match.in_port = 3
              msgh.actions.append(of.ofp_action_output(port = 2))
              sHW.addRegra(msgh)
            else:
              log.info("%s: Porta de protocolo IMPAR, encaminhando para switch SW." % (self.nome))
              #Porta de saida para o switch SW
              port = 3
              global sSW
              msgs = of.ofp_flow_mod()
              msgs.match = of.ofp_match.from_packet(packet, event.port)
              msgs.match.in_port = 1
              msgs.actions.append(of.ofp_action_output(port = 2))
              sSW.addRegra(msgs)
          #Caso nao tenha porta de protocolo, o pacote nao e TCP nem UDP entao encaminha para o SW
          else:
            log.info("%s: Trafego diferente de TCP/UDP, encaminhando para switch SW." % (self.nome))
            #Porta de saida para o switch SW
            port = 3
            global sSW
            msgs = of.ofp_flow_mod()
            msgs.match = of.ofp_match.from_packet(packet, event.port)
            msgs.match.in_port = 1
            msgs.actions.append(of.ofp_action_output(port = 2))
            sSW.addRegra(msgs)

        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp
      
        log.info("%s: Instalando regra %s nas portas %i -> %i" % (self.nome, protocolo, event.port, port))
        self.connection.send(msg)
      else:
        #port = self.macToPort[packet.dst]
        port = 2
        msg = of.ofp_flow_mod()
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp
        msg.match = of.ofp_match.from_packet(packet, event.port)
        self.connection.send(msg)



#Aguarda a conexao de um switch OpenFlow e cria learning switches
class l2_learning (object):
  def __init__ (self, ignore = None):
    #Listeners
    core.openflow.addListeners(self)
    #Switches para ignorar
    self.ignore = set(ignore) if ignore else ()

  def _handle_ConnectionUp (self, event):
    if event.dpid in self.ignore:
      log.debug("Ignorando conexao de: %s" % (event.connection,))
      return
    log.debug("Conexao %s" % (event.connection,))
    #Verificando qual switch esta sendo conectado e colocando eles nas variaveis
    if (dpid_to_str(event.dpid) == '00-e0-4c-2a-33-4f'):
      global sUL
      sUL = LearningSwitch(event.connection, 'Switch UL')
      log.info ('Switch UL conectado.')
    elif (dpid_to_str(event.dpid) == '00-08-54-aa-cb-bc'):
      global sDL
      sDL = LearningSwitch(event.connection, 'Switch DL')
      log.info ('Switch DL conectado.')
    elif (dpid_to_str(event.dpid) == '00-06-4f-86-af-ff'):
      global sHW
      sHW = LearningSwitch(event.connection, 'Switch HW')
      log.info ('Switch HW conectado.')
    elif (dpid_to_str(event.dpid) == '00-40-a7-0c-01-75'):
      global sSW
      sSW = LearningSwitch(event.connection, 'Switch SW')
      log.info ('Switch SW conectado.')
    else:
      LearningSwitch(event.connection, 'Switch Desconhecido')
      log.info ('Switch nao identificado conectado.')

def launch (ignore = None):
  #Inicializa o controlador
  if ignore:
    ignore = ignore.replace(',', ' ').split()
    ignore = set(str_to_dpid(dpid) for dpid in ignore)
  core.registerNew(l2_learning, ignore)