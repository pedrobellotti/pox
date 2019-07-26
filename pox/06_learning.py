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
      self.macToPort[packet.src] = event.port #Adiciona na tabela a porta para o mac
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, event.port)
      #Informacoes do pacote e da regra
      dltype = msg.match.dl_type
      inport = msg.match.in_port
      dlsrc = msg.match.dl_src
      dldst = msg.match.dl_dst
      nwsrc = msg.match.nw_src
      nwdst = msg.match.nw_dst
      #protocolo = msg.match.nw_proto
      #msg.idle_timeout = 500
      #msg.hard_timeout = 600
      if (self.nome == 'Switch DL'):
        port = 3
        #Criando regra no switch UL
        global sUL
        msgu = of.ofp_flow_mod()
        msgu.match = of.ofp_match.from_packet(packet, event.port)
        msgu.match.in_port = 4
        msgu.actions.append(of.ofp_action_output(port = 2))
        sUL.addRegra(msgu)
      elif (self.nome == 'Switch UL'):
        port = 4
        global sDL
        msgd = of.ofp_flow_mod()
        msgd.match = of.ofp_match.from_packet(packet, event.port)
        msgd.match.in_port = 3
        msgd.actions.append(of.ofp_action_output(port = 2))
        sDL.addRegra(msgd)
      msg.actions.append(of.ofp_action_output(port = port))
      msg.data = event.ofp
      protocolo = 'Nao identificado'
      try:
        tcp_found = packet.find('tcp')
        udp_found = packet.find('udp')
        arp_found = packet.find('arp')
        icmp_found = packet.find('icmp')
        if tcp_found:
          protocolo = 'TCP'
        elif udp_found:
          protocolo = 'UDP'
        elif arp_found:
          protocolo = 'ARP'
        elif icmp_found:
          protocolo = 'ICMP'
      except:
        protocolo = 'Nao identificado'
      #Informacoes de portas TCP/UDP
      if (protocolo == 'UDP' or protocolo == 'TCP'):
        if (msg.match.tp_src is not None and msg.match.tp_dst is not None):
          protosrc = msg.match.tp_src
          protodst = msg.match.tp_dst
        else:
          protosrc = 0
          protodst = 0
        log.info("%s: Instalando regra %s nas portas %i -> %i / %i -> %i" % (self.nome, protocolo, event.port, port, protosrc, protodst))
      else:
        log.info("%s: Instalando regra %s nas portas %i -> %i" % (self.nome, protocolo, event.port, port))
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
    elif (dpid_to_str(event.dpid) == '00-40-af-0c-01-75'):
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
