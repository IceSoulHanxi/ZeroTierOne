/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2026-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

#include "Constants.hpp"
#include "Topology.hpp"
#include "RuntimeEnvironment.hpp"
#include "Node.hpp"
#include "Network.hpp"
#include "NetworkConfig.hpp"
#include "Buffer.hpp"
#include "Switch.hpp"

namespace ZeroTier {

#include "../attic/world/world.c"

Topology::Topology(const RuntimeEnvironment *renv,void *tPtr) :
	RR(renv),
	_numConfiguredPhysicalPaths(0),
	_amUpstream(false)
{
	uint8_t tmp[ZT_WORLD_MAX_SERIALIZED_LENGTH];
	uint64_t idtmp[2];
	idtmp[0] = 0;
	idtmp[1] = 0;
	int n = RR->node->stateObjectGet(tPtr,ZT_STATE_OBJECT_PLANET,idtmp,tmp,sizeof(tmp));
	if (n > 0) {
		try {
			World cachedPlanet;
			cachedPlanet.deserialize(Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH>(tmp,(unsigned int)n),0);
			addWorld(tPtr,cachedPlanet,false);
		} catch ( ... ) {} // ignore invalid cached planets
	}

	World defaultPlanet;
	{
		Buffer<ZT_DEFAULT_WORLD_LENGTH> wtmp(ZT_DEFAULT_WORLD,ZT_DEFAULT_WORLD_LENGTH);
		defaultPlanet.deserialize(wtmp,0); // throws on error, which would indicate a bad static variable up top
	}
	addWorld(tPtr,defaultPlanet,false);
}

Topology::~Topology()
{
	Hashtable< Address,SharedPtr<Peer> >::Iterator i(_peers);
	Address *a = (Address *)0;
	SharedPtr<Peer> *p = (SharedPtr<Peer> *)0;
	while (i.next(a,p)) {
		_savePeer((void *)0,*p);
	}
}

SharedPtr<Peer> Topology::addPeer(void *tPtr,const SharedPtr<Peer> &peer)
{
	SharedPtr<Peer> np;
	{
		Mutex::Lock _l(_peers_m);
		SharedPtr<Peer> &hp = _peers[peer->address()];
		if (!hp) {
			hp = peer;
		}
		np = hp;
	}
	return np;
}

SharedPtr<Peer> Topology::getPeer(void *tPtr,const Address &zta)
{
	if (zta == RR->identity.address()) {
		return SharedPtr<Peer>();
	}

	{
		Mutex::Lock _l(_peers_m);
		const SharedPtr<Peer> *const ap = _peers.get(zta);
		if (ap) {
			return *ap;
		}
	}

	try {
		Buffer<ZT_PEER_MAX_SERIALIZED_STATE_SIZE> buf;
		uint64_t idbuf[2];
		idbuf[0] = zta.toInt();
		idbuf[1] = 0;
		int len = RR->node->stateObjectGet(tPtr,ZT_STATE_OBJECT_PEER,idbuf,buf.unsafeData(),ZT_PEER_MAX_SERIALIZED_STATE_SIZE);
		if (len > 0) {
			buf.setSize(len);
			Mutex::Lock _l(_peers_m);
			SharedPtr<Peer> &ap = _peers[zta];
			if (ap) {
				return ap;
			}
			ap = Peer::deserializeFromCache(RR->node->now(),tPtr,buf,RR);
			if (!ap) {
				_peers.erase(zta);
			}
			return SharedPtr<Peer>();
		}
	} catch ( ... ) {} // ignore invalid identities or other strange failures

	return SharedPtr<Peer>();
}

Identity Topology::getIdentity(void *tPtr,const Address &zta)
{
	if (zta == RR->identity.address()) {
		return RR->identity;
	} else {
		Mutex::Lock _l(_peers_m);
		const SharedPtr<Peer> *const ap = _peers.get(zta);
		if (ap) {
			return (*ap)->identity();
		}
	}
	return Identity();
}

SharedPtr<Peer> Topology::getUpstreamPeer()
{
	const int64_t now = RR->node->now();
	unsigned int bestq = ~((unsigned int)0);
	const SharedPtr<Peer> *best = (const SharedPtr<Peer> *)0;

	Mutex::Lock _l2(_peers_m);
	Mutex::Lock _l1(_upstreams_m);

	for(std::vector<Address>::const_iterator a(_upstreamAddresses.begin());a!=_upstreamAddresses.end();++a) {
		const SharedPtr<Peer> *p = _peers.get(*a);
		if (p) {
			const unsigned int q = (*p)->relayQuality(now);
			if (q <= bestq) {
				bestq = q;
				best = p;
			}
		}
	}

	if (!best) {
		return SharedPtr<Peer>();
	}
	return *best;
}

bool Topology::isUpstream(const Identity &id) const
{
	Mutex::Lock _l(_upstreams_m);
	return (std::find(_upstreamAddresses.begin(),_upstreamAddresses.end(),id.address()) != _upstreamAddresses.end());
}

bool Topology::shouldAcceptWorldUpdateFrom(const Address &addr) const
{
	Mutex::Lock _l(_upstreams_m);
	if (std::find(_upstreamAddresses.begin(),_upstreamAddresses.end(),addr) != _upstreamAddresses.end()) {
		return true;
	}
	for(std::vector< std::pair< uint64_t,Address> >::const_iterator s(_moonSeeds.begin());s!=_moonSeeds.end();++s) {
		if (s->second == addr) {
			return true;
		}
	}
	return false;
}

ZT_PeerRole Topology::role(const Address &ztaddr) const
{
	Mutex::Lock _l(_upstreams_m);
	if (std::find(_upstreamAddresses.begin(),_upstreamAddresses.end(),ztaddr) != _upstreamAddresses.end()) {
		for(std::vector<World::Root>::const_iterator i(_planet.roots().begin());i!=_planet.roots().end();++i) {
			if (i->identity.address() == ztaddr) {
				return ZT_PEER_ROLE_PLANET;
			}
		}
		return ZT_PEER_ROLE_MOON;
	}
	return ZT_PEER_ROLE_LEAF;
}

bool Topology::isProhibitedEndpoint(const Address &ztaddr,const InetAddress &ipaddr) const
{
	Mutex::Lock _l(_upstreams_m);

	// For roots the only permitted addresses are those defined. This adds just a little
	// bit of extra security against spoofing, replaying, etc.
	if (std::find(_upstreamAddresses.begin(),_upstreamAddresses.end(),ztaddr) != _upstreamAddresses.end()) {
		for(std::vector<World::Root>::const_iterator r(_planet.roots().begin());r!=_planet.roots().end();++r) {
			if (r->identity.address() == ztaddr) {
				if (r->stableEndpoints.empty()) {
					return false; // no stable endpoints specified, so allow dynamic paths
				}
				for(std::vector<InetAddress>::const_iterator e(r->stableEndpoints.begin());e!=r->stableEndpoints.end();++e) {
					if (ipaddr.ipsEqual(*e)) {
						return false;
					}
				}
			}
		}
		for(std::vector<World>::const_iterator m(_moons.begin());m!=_moons.end();++m) {
			for(std::vector<World::Root>::const_iterator r(m->roots().begin());r!=m->roots().end();++r) {
				if (r->identity.address() == ztaddr) {
					if (r->stableEndpoints.empty()) {
						return false; // no stable endpoints specified, so allow dynamic paths
					}
					for(std::vector<InetAddress>::const_iterator e(r->stableEndpoints.begin());e!=r->stableEndpoints.end();++e) {
						if (ipaddr.ipsEqual(*e)) {
							return false;
						}
					}
				}
			}
		}
		return true;
	}

	return false;
}

bool Topology::addWorld(void *tPtr,const World &newWorld,bool alwaysAcceptNew)
{
	if ((newWorld.type() != World::TYPE_PLANET)&&(newWorld.type() != World::TYPE_MOON)) {
		return false;
	}

	Mutex::Lock _l2(_peers_m);
	Mutex::Lock _l1(_upstreams_m);

	World *existing = (World *)0;
	switch(newWorld.type()) {
		case World::TYPE_PLANET:
			existing = &_planet;
			break;
		case World::TYPE_MOON:
			for(std::vector< World >::iterator m(_moons.begin());m!=_moons.end();++m) {
				if (m->id() == newWorld.id()) {
					existing = &(*m);
					break;
				}
			}
			break;
		default:
			return false;
	}

	if (existing) {
		if (existing->shouldBeReplacedBy(newWorld)) {
			*existing = newWorld;
		} else {
			return false;
		}
	} else if (newWorld.type() == World::TYPE_MOON) {
		if (alwaysAcceptNew) {
			_moons.push_back(newWorld);
			existing = &(_moons.back());
		} else {
			for(std::vector< std::pair<uint64_t,Address> >::iterator m(_moonSeeds.begin());m!=_moonSeeds.end();++m) {
				if (m->first == newWorld.id()) {
					for(std::vector<World::Root>::const_iterator r(newWorld.roots().begin());r!=newWorld.roots().end();++r) {
						if (r->identity.address() == m->second) {
							_moonSeeds.erase(m);
							_moons.push_back(newWorld);
							existing = &(_moons.back());
							break;
						}
					}
					if (existing) {
						break;
					}
				}
			}
		}
		if (!existing) {
			return false;
		}
	} else {
		return false;
	}

	try {
		Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH> sbuf;
		existing->serialize(sbuf,false);
		uint64_t idtmp[2];
		idtmp[0] = existing->id();
		idtmp[1] = 0;
		RR->node->stateObjectPut(tPtr,(existing->type() == World::TYPE_PLANET) ? ZT_STATE_OBJECT_PLANET : ZT_STATE_OBJECT_MOON,idtmp,sbuf.data(),sbuf.size());
	} catch ( ... ) {}

	_memoizeUpstreams(tPtr);

	return true;
}

void Topology::addMoon(void *tPtr,const uint64_t id,const Address &seed)
{
	char tmp[ZT_WORLD_MAX_SERIALIZED_LENGTH];
	uint64_t idtmp[2];
	idtmp[0] = id;
	idtmp[1] = 0;
	int n = RR->node->stateObjectGet(tPtr,ZT_STATE_OBJECT_MOON,idtmp,tmp,sizeof(tmp));
	if (n > 0) {
		try {
			World w;
			w.deserialize(Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH>(tmp,(unsigned int)n));
			if ((w.type() == World::TYPE_MOON)&&(w.id() == id)) {
				addWorld(tPtr,w,true);
				return;
			}
		} catch ( ... ) {}
	}

	if (seed) {
		Mutex::Lock _l(_upstreams_m);
		if (std::find(_moonSeeds.begin(),_moonSeeds.end(),std::pair<uint64_t,Address>(id,seed)) == _moonSeeds.end()) {
			_moonSeeds.push_back(std::pair<uint64_t,Address>(id,seed));
		}
	}
}

void Topology::removeMoon(void *tPtr,const uint64_t id)
{
	Mutex::Lock _l2(_peers_m);
	Mutex::Lock _l1(_upstreams_m);

	std::vector<World> nm;
	for(std::vector<World>::const_iterator m(_moons.begin());m!=_moons.end();++m) {
		if (m->id() != id) {
			nm.push_back(*m);
		} else {
			uint64_t idtmp[2];
			idtmp[0] = id;
			idtmp[1] = 0;
			RR->node->stateObjectDelete(tPtr,ZT_STATE_OBJECT_MOON,idtmp);
		}
	}
	_moons.swap(nm);

	std::vector< std::pair<uint64_t,Address> > cm;
	for(std::vector< std::pair<uint64_t,Address> >::const_iterator m(_moonSeeds.begin());m!=_moonSeeds.end();++m) {
		if (m->first != id) {
			cm.push_back(*m);
		}
	}
	_moonSeeds.swap(cm);

	_memoizeUpstreams(tPtr);
}

void Topology::doPeriodicTasks(void *tPtr,int64_t now)
{
	{
		Mutex::Lock _l1(_peers_m);
		Mutex::Lock _l2(_upstreams_m);
		Hashtable< Address,SharedPtr<Peer> >::Iterator i(_peers);
		Address *a = (Address *)0;
		SharedPtr<Peer> *p = (SharedPtr<Peer> *)0;
		while (i.next(a,p)) {
			if ( (!(*p)->isAlive(now)) && (std::find(_upstreamAddresses.begin(),_upstreamAddresses.end(),*a) == _upstreamAddresses.end()) ) {
				_savePeer(tPtr,*p);
				_peers.erase(*a);
			}
		}
	}

	{
		Mutex::Lock _l(_paths_m);
		Hashtable< Path::HashKey,SharedPtr<Path> >::Iterator i(_paths);
		Path::HashKey *k = (Path::HashKey *)0;
		SharedPtr<Path> *p = (SharedPtr<Path> *)0;
		while (i.next(k,p)) {
			if (p->references() <= 1) {
				_paths.erase(*k);
			}
		}
	}
}

void Topology::_memoizeUpstreams(void *tPtr)
{
	// assumes _upstreams_m and _peers_m are locked
	_upstreamAddresses.clear();
	_amUpstream = false;

	for(std::vector<World::Root>::const_iterator i(_planet.roots().begin());i!=_planet.roots().end();++i) {
		const Identity &id = i->identity;
		if (id == RR->identity) {
			_amUpstream = true;
		} else if (std::find(_upstreamAddresses.begin(),_upstreamAddresses.end(),id.address()) == _upstreamAddresses.end()) {
			_upstreamAddresses.push_back(id.address());
			SharedPtr<Peer> &hp = _peers[id.address()];
			if (!hp) {
				hp = new Peer(RR,RR->identity,id);
			}
		}
	}

	for(std::vector<World>::const_iterator m(_moons.begin());m!=_moons.end();++m) {
		for(std::vector<World::Root>::const_iterator i(m->roots().begin());i!=m->roots().end();++i) {
			if (i->identity == RR->identity) {
				_amUpstream = true;
			} else if (std::find(_upstreamAddresses.begin(),_upstreamAddresses.end(),i->identity.address()) == _upstreamAddresses.end()) {
				_upstreamAddresses.push_back(i->identity.address());
				SharedPtr<Peer> &hp = _peers[i->identity.address()];
				if (!hp) {
					hp = new Peer(RR,RR->identity,i->identity);
				}
			}
		}
	}

	std::sort(_upstreamAddresses.begin(),_upstreamAddresses.end());
}

void Topology::_savePeer(void *tPtr,const SharedPtr<Peer> &peer)
{
	try {
		Buffer<ZT_PEER_MAX_SERIALIZED_STATE_SIZE> buf;
		peer->serializeForCache(buf);
		uint64_t tmpid[2];
		tmpid[0] = peer->address().toInt();
		tmpid[1] = 0;
		RR->node->stateObjectPut(tPtr,ZT_STATE_OBJECT_PEER,tmpid,buf.data(),buf.size());
	} catch ( ... ) {} // sanity check, discard invalid entries
}

} // namespace ZeroTier
