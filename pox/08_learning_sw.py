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
from pox.lib.util import dpid_to_str, str_to_dpid, dpidToStr, str_to_bool
from pox.lib.recoco import Timer
from pox.openflow.of_json import flow_stats_to_list
from pox.lib.addresses import IPAddr, EthAddr
import time
from threading import Timer as Delay

log = core.getLogger()
sHW = None
sSW = None
sUL = None
sDL = None

#Maximo de regras no switch HW
MAXREGRAS = 200

#Tempo de inicio
TEMPOINI = time.time()

#Tempo (segundos) para adicionar regras no HW
TEMPOADD = 0.5

#Tempo (segundos) para modificar as regras no UL/DL
TEMPOMOD = TEMPOADD+1

#Tempo (segundos) para remover as regras no SW
TEMPODEL = TEMPOMOD+0.5

class LearningSwitch (object):
  #Inicializa o switch
  def __init__ (self, connection, nome):
    # Conexao com o switch
    self.connection = connection
    # Tabela MAC->Porta
    self.macToPort = {}
    # Listeners
    connection.addListeners(self)
    # Nome do switch
    self.nome = nome
    # Tabela de regras
    self.tabela = None
    # Contador de regras do switch
    self.numRegras = 0
    # Contador de regras aceitas
    self.numAceitas = 0
    # Contador de regras bloqueadas
    self.numBloqueadas = 0
    # Contador de bytes enviados (total)
    self.bytesEnviados = 0
    # Lista de portas ja verificadas (packet-in)
    self.listaPortas = []
    # Controla se deve trocar ou nao as regras
    self.trocar = 1

  # Inicia o timer para verificar estatisticas das regras
  def iniciarTimer(self):
    Timer(5, self.getflowstats, recurring=False)

  #Adiciona uma regra no switch
  def addRegra (self, regra):
    regra.flags |= of.OFPFF_SEND_FLOW_REM
    self.connection.send(regra)
    log.debug ('%s: Regra adicionada' % (self.nome))
    self.numRegras += 1
    self.numAceitas += 1
    #print regra

  #Remove uma regra no switch
  def delRegra (self, regra):
    self.connection.send(of.ofp_flow_mod(match=regra,command=of.OFPFC_DELETE))
    log.debug ('%s: Regra removida' % (self.nome))
    #print regra
  
  #Retorna numero de regras no switch
  def getNumregras (self):
    return self.numRegras

  #Retorna numero total de regras aceitas no switch
  def getNumAceitas (self):
    return self.numAceitas

  #Retorna numero total de regras bloqueadas no switch
  def getNumBloqueadas (self):
    return self.numBloqueadas

  #Aumenta o contador de regras bloqueadas
  def aumentaBloqueada (self):
    self.numBloqueadas += 1

  #Flow removed
  def _handle_FlowRemoved(self, event):
    log.debug("%s: Regra expirada ou removida", self.nome)
    self.numRegras -= 1
    self.bytesEnviados += event.ofp.byte_count

  #Pede estatisticas de fluxo do switch
  def getflowstats(self):
    log.debug("Enviando pedido de estatisticas para " + self.nome)
    self.connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

  #Trata as estatisticas do switch e move regras
  def _handle_FlowStatsReceived (self, event):
    #self.tabela = event.stats
    self.listaPortas = []
    stats = flow_stats_to_list(event.stats) #Todas as regras em uma lista
    #log.info("%s: FlowStatsReceived -> %s", self.nome, stats)
    self.numRegras = len(stats)
    if (self.nome == "Switch HW"):
      self.flowStatsHW(event)
      f = open("info_sw.txt", "a+")
      f.write("%d HW %d %d %d %d\n" % (time.time()-TEMPOINI, sHW.getNumregras(), sHW.getNumAceitas(), sHW.getNumBloqueadas(), self.bytesEnviados))
      f.close()
      self.iniciarTimer()
    elif (self.nome == "Switch SW"):
      self.flowStatsSW(event)
      f = open("info_sw.txt", "a+")
      f.write("%d SW %d %d %d %d\n" % (time.time()-TEMPOINI, sSW.getNumregras(), sSW.getNumAceitas(), sSW.getNumBloqueadas(), self.bytesEnviados))
      f.close()
      self.iniciarTimer()
    elif (self.nome == "Switch UL"):
      self.flowStatsUL(event)
    elif (self.nome == "Switch DL"):
      self.flowStatsDL(event)

  #Handler para HW
  def flowStatsHW (self, event):
    log.info ("%s: Numero de regras instaladas: %d", self.nome, self.numRegras)
    '''
    for regra in event.stats:
      if (regra.duration_sec > 12 and regra.cookie != 55):
        log.debug ("Trocando regra HW->SW")
        #Adiciona regra no SW
        reg = of.ofp_flow_mod()
        reg.match = regra.match
        #Alterando in_port
        if (regra.match.in_port == 3):
          reg.match.in_port = 1
          reg.actions.append(of.ofp_action_output(port = 2))
        else:
          reg.match.in_port = 2
          reg.actions.append(of.ofp_action_output(port = 1))
        reg.priority = regra.priority
        reg.idle_timeout = regra.idle_timeout
        reg.hard_timeout = regra.hard_timeout
        #reg.cookie = regra.cookie + 1 #Conta quantas vezes a regra foi trocada de switch
        sSW.addRegra (reg)
        if (regra.match.nw_dst == IPAddr('10.1.0.1')):
          #Alterando regra no UL
          regUL = of.ofp_match()
          regUL.nw_proto = regra.match.nw_proto
          regUL.dl_type = regra.match.dl_type
          regUL.nw_src = IPAddr('10.1.0.2')
          regUL.nw_dst = IPAddr('10.1.0.1')
          regUL.tp_dst = regra.match.tp_dst
          regUL.tp_src = regra.match.tp_src
          regUL.in_port = 2
          sUL.addRegra(of.ofp_flow_mod(match=regUL, command=of.OFPFC_MODIFY, actions=[of.ofp_action_output(port=3)]))
        elif (regra.match.nw_dst == IPAddr('10.1.0.2')):
          #Alterando regra no DL
          regDL = of.ofp_match()
          regDL.nw_proto = regra.match.nw_proto
          regDL.dl_type = regra.match.dl_type
          regDL.nw_dst = IPAddr('10.1.0.2')
          regDL.nw_src = IPAddr('10.1.0.1')
          regDL.tp_dst = regra.match.tp_dst
          regDL.tp_src = regra.match.tp_src
          regDL.in_port = 2
          sDL.addRegra(of.ofp_flow_mod(match=regDL, command=of.OFPFC_MODIFY, actions=[of.ofp_action_output(port=3)]))
        #Remove regra no HW
        self.delRegra (regra.match)
    '''

  #Handler para SW
  def flowStatsSW (self, event):
    log.info ("%s: Numero de regras instaladas: %d", self.nome, self.numRegras)
    quant = sHW.getNumregras()
    if (quant >= MAXREGRAS):
      log.info ("%s: Lista de regras do HW cheia, nao move regras", self.nome)
      sHW.aumentaBloqueada()
      return
    if (self.trocar < 2):
      log.debug ("%s: Nao esta na hora de trocar regras.", self.nome)
      self.trocar += 1 #Aumenta o contador
      return
    else:
      log.debug ("%s: Trocando regras.", self.nome)
      self.trocar = 1 #Resta o contador
    regrasOrdenadas = sorted(event.stats, key=lambda x: x.byte_count/x.duration_sec if x.duration_sec > 0 else 0, reverse=True) 
    regrasInseridas = 0
    limite = MAXREGRAS-quant
    log.info("%s: Pode mover %d regra(s) para o switch HW.", self.nome, limite)
    for regra in regrasOrdenadas:
      #Movendo regra do switch SW para o switch HW
      if (regra.cookie == 55 or (regra.match.nw_proto != 6 and regra.match.nw_proto != 17)):
        continue #Ignora as regras fixas e regras de arp
      if (regrasInseridas < limite):
        #Adiciona regra no HW
        reg = of.ofp_flow_mod()
        reg.match = regra.match
        #Alterando in_port
        if (regra.match.in_port == 1):
          reg.match.in_port = 3
          reg.actions.append(of.ofp_action_output(port = 2))
        else:
          reg.match.in_port = 2
          reg.actions.append(of.ofp_action_output(port = 3))
        reg.priority = regra.priority
        reg.idle_timeout = regra.idle_timeout
        reg.hard_timeout = regra.hard_timeout
        #reg.cookie = regra.cookie + 1 #Conta quantas vezes a regra foi trocada de switch
        #sHW.addRegra (reg)
        t = Delay(TEMPOADD, sHW.addRegra, [reg])
        t.start()
        if (regra.match.nw_dst == IPAddr('10.1.0.1')):
          #Alterando regra no UL
          regUL = of.ofp_match()
          regUL.nw_proto = regra.match.nw_proto
          regUL.dl_type = regra.match.dl_type
          regUL.nw_src = IPAddr('10.1.0.2')
          regUL.nw_dst = IPAddr('10.1.0.1')
          regUL.tp_dst = regra.match.tp_dst
          regUL.tp_src = regra.match.tp_src
          regUL.in_port = 2
          #sUL.addRegra(of.ofp_flow_mod(match=regUL, command=of.OFPFC_MODIFY, actions=[of.ofp_action_output(port=1)]))
          mod = of.ofp_flow_mod(match=regUL, command=of.OFPFC_MODIFY, actions=[of.ofp_action_output(port=1)])
          t1 = Delay(TEMPOMOD, sUL.addRegra, [mod])
          t1.start()
        elif (regra.match.nw_dst == IPAddr('10.1.0.2')):
          #Alterando regra no DL
          regDL = of.ofp_match()
          regDL.nw_proto = regra.match.nw_proto
          regDL.dl_type = regra.match.dl_type
          regDL.nw_dst = IPAddr('10.1.0.2')
          regDL.nw_src = IPAddr('10.1.0.1')
          regDL.tp_dst = regra.match.tp_dst
          regDL.tp_src = regra.match.tp_src
          regDL.in_port = 2
          #sDL.addRegra(of.ofp_flow_mod(match=regDL, command=of.OFPFC_MODIFY, actions=[of.ofp_action_output(port=4)])),
          mod = of.ofp_flow_mod(match=regDL, command=of.OFPFC_MODIFY, actions=[of.ofp_action_output(port=4)])
          t2 = Delay(TEMPOMOD, sDL.addRegra, [mod])
          t2.start()
        #Remove regra no SW
        #self.delRegra (regra.match)
        dele = regra.match
        t3 = Delay(TEMPODEL, self.delRegra, [dele])
        t3.start()
        #Aumenta o contador
        regrasInseridas += 1
      else:
        log.info("%s: Regras movidas: %d", self.nome, regrasInseridas)
        return

  #Handler para DL
  def flowStatsDL (self, event):
    log.info ("%s: Numero de regras instaladas: %d", self.nome, self.numRegras)

  #Handler para UL
  def flowStatsUL (self, event):
    log.info ("%s: Numero de regras instaladas: %d", self.nome, self.numRegras)

  #Packet In
  def _handle_PacketIn (self, event):
    packet = event.parsed #"Abre" o pacote
    if (packet.next.find('IPV6') or packet.next.find('ipv6')):
      log.debug("Ignorando pacote IPv6")
      return
    #log.debug("%s: Packet in", self.nome)
    #Somente os switches DL e UL possem aprendizado de portas
    if (self.nome == 'Switch DL'):
      self.packetInDL(event, packet)
    elif (self.nome == 'Switch UL'):
      self.packetInUL(event, packet)

  def packetInDL(self, event, packet):
    if (event.port == 2):
      self.macToPort[packet.src] = event.port #Adiciona na tabela a porta para o mac
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, event.port)
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
          if (protosrc in self.listaPortas):
            log.debug("%s: Packet in para porta ja atendida, ignorando." % (self.nome))
            return
          else:
            self.listaPortas.append(protosrc)

      #Logica de divisao de trafego
      # !!! Numero das portas nas regras podem mudar caso os cabos troquem de lugar !!!
      #Envia todo o trafego para o switch SW
      log.debug("%s: Encaminhando para switch SW." % (self.nome))
      #Porta de saida para o switch SW
      port = 3
      global sSW
      msgs = of.ofp_flow_mod()
      msgs.match = of.ofp_match.from_packet(packet, event.port)
      msgs.match.in_port = 2
      msgs.actions.append(of.ofp_action_output(port = 1))
      msgs.idle_timeout = 15
      sSW.addRegra(msgs)

      msg.actions.append(of.ofp_action_output(port = port))
      msg.idle_timeout = 15
      msg.data = event.ofp

      log.debug("%s: Instalando regra %s nas portas %i -> %i" % (self.nome, protocolo, event.port, port))
      self.addRegra(msg)

  def packetInUL(self, event, packet):
    if (event.port == 2):
      self.macToPort[packet.src] = event.port #Adiciona na tabela a porta para o mac
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, event.port)
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
          if (protosrc in self.listaPortas):
            log.debug("%s: Packet in para porta ja atendida, ignorando." % (self.nome))
            return
          else:
            self.listaPortas.append(protosrc)

      #Logica da divisao de trafego
      # !!! Numero das portas nas regras podem mudar caso os cabos troquem de lugar !!!
      #Envia todo o trafego para o switch SW
      log.debug("%s: Encaminhando para switch SW." % (self.nome))
      #Porta de saida para o switch SW
      port = 3
      global sSW
      msgs = of.ofp_flow_mod()
      msgs.match = of.ofp_match.from_packet(packet, event.port)
      msgs.match.in_port = 1
      msgs.actions.append(of.ofp_action_output(port = 2))
      msgs.idle_timeout = 15
      sSW.addRegra(msgs)

      msg.actions.append(of.ofp_action_output(port = port))
      msg.idle_timeout = 15
      msg.data = event.ofp
      log.debug("%s: Instalando regra %s nas portas %i -> %i" % (self.nome, protocolo, event.port, port))
      self.addRegra(msg)

#Aguarda a conexao de um switch OpenFlow e cria learning switches
class l2_learning (object):
  def __init__ (self, ignore = None):
    #Listeners
    core.openflow.addListeners(self)
    #Switches para ignorar
    self.ignore = set(ignore) if ignore else ()
    #Contador de switches conectados
    self.contador = 0

  def addRegraPing (self, event):
    #Regra de ida par (HW)
    reg = of.ofp_flow_mod()
    reg.cookie = 55
    reg.match.nw_proto = 17
    reg.match.dl_type = 0x800
    reg.match.nw_dst = IPAddr('10.1.0.2')
    reg.match.nw_src = IPAddr('10.1.0.1')
    reg.match.tp_dst = 65534
    reg.match.tp_src = 7000
    regHW = reg
    reg.match.in_port = 2
    reg.actions.append(of.ofp_action_output(port = 4))
    global sDL
    sDL.addRegra(reg)
    regHW.match.in_port = 2
    regHW.actions.append(of.ofp_action_output(port = 3))
    global sHW
    sHW.addRegra(regHW)

    #Regra de volta par (HW)
    reg2 = of.ofp_flow_mod()
    reg2.cookie = 55
    reg2.match.nw_proto = 17
    reg2.match.dl_type = 0x800
    reg2.match.nw_src = IPAddr('10.1.0.2')
    reg2.match.nw_dst = IPAddr('10.1.0.1')
    reg2.match.tp_src = 65534
    reg2.match.tp_dst = 7000
    regHW2 = reg2
    reg2.match.in_port = 2
    reg2.actions.append(of.ofp_action_output(port = 1))
    global sUL
    sUL.addRegra(reg2)
    regHW2.match.in_port = 3
    regHW2.actions.append(of.ofp_action_output(port = 2))
    global sHW
    sHW.addRegra(regHW2)

    #Regra de ida impar (SW)
    reg3 = of.ofp_flow_mod()
    reg3.cookie = 55
    reg3.match.nw_proto = 17
    reg3.match.dl_type = 0x800
    reg3.match.nw_dst = IPAddr('10.1.0.2')
    reg3.match.nw_src = IPAddr('10.1.0.1')
    reg3.match.tp_dst = 65535
    reg3.match.tp_src = 7001
    regSW = reg3
    reg3.match.in_port = 2
    reg3.actions.append(of.ofp_action_output(port = 3))
    global sDL
    sDL.addRegra(reg3)
    regSW.match.in_port = 2
    regSW.actions.append(of.ofp_action_output(port = 1))
    global sSW
    sSW.addRegra(regSW)

    #Regra de volta impar (SW)
    reg4 = of.ofp_flow_mod()
    reg4.cookie = 55
    reg4.match.nw_proto = 17
    reg4.match.dl_type = 0x800
    reg4.match.nw_src = IPAddr('10.1.0.2')
    reg4.match.nw_dst = IPAddr('10.1.0.1')
    reg4.match.tp_src = 65535
    reg4.match.tp_dst = 7001
    regSW2 = reg4
    reg4.match.in_port = 2
    reg4.actions.append(of.ofp_action_output(port = 3))
    global sUL
    sUL.addRegra(reg4)
    regSW2.match.in_port = 1
    regSW2.actions.append(of.ofp_action_output(port = 2))
    global sSW
    sSW.addRegra(regSW2)

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
      #Regras basicas no UL (chegando em qualquer porta, envia para 2)
      msg = of.ofp_flow_mod()
      msg.match.in_port = 3
      msg.actions.append(of.ofp_action_output(port = 2))
      msg.priority = 10
      sUL.addRegra(msg)
      msg2 = of.ofp_flow_mod()
      msg2.match.in_port = 1
      msg2.actions.append(of.ofp_action_output(port = 2))
      msg2.priority = 10
      sUL.addRegra(msg2)
    elif (dpid_to_str(event.dpid) == '00-08-54-aa-cb-bc'):
      global sDL
      sDL = LearningSwitch(event.connection, 'Switch DL')
      log.info ('Switch DL conectado.')
      #Regras basicas no DL (chegando em qualquer porta, envia para 2)
      msg = of.ofp_flow_mod()
      msg.match.in_port = 3
      msg.actions.append(of.ofp_action_output(port = 2))
      msg.priority = 10
      sDL.addRegra(msg)
      msg2 = of.ofp_flow_mod()
      msg2.match.in_port = 4
      msg2.actions.append(of.ofp_action_output(port = 2))
      msg2.priority = 10
      sDL.addRegra(msg2)
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
    self.contador += 1
    if (self.contador == 4):
      self.addRegraPing(event)
      #sUL.iniciarTimer()
      #sDL.iniciarTimer()
      sHW.iniciarTimer()
      sSW.iniciarTimer()

def launch (ignore = None):
  #Inicializa o controlador
  if ignore:
    ignore = ignore.replace(',', ' ').split()
    ignore = set(str_to_dpid(dpid) for dpid in ignore)
  #Cria arquivo de estatisticas
  f = open("info_sw.txt", "a+")
  f.write ("Tempo Switch RegrasInstaladas RegrasAceitas VezesBloqueado BytesEnviados\n")
  f.close()
  core.registerNew(l2_learning, ignore)
