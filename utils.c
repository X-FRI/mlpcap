/*      MLpcap: pcap bindings for OCaml.
 *      Copyright (C) 2003-2004 Jonathan Heusser <jonny@drugphish.ch>
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2.1 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library; if not, write to the Free Software
 *      Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */
#include <stddef.h>
#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/callback.h>
#ifdef Custom_tag
#include <caml/custom.h>
#include <caml/bigarray.h>
#endif
#include <caml/camlidlruntime.h>

#include <callback.h>
#include <pcap.h>
#include "utils.h"

void
_pcap_callback (void *cback, va_alist alist)
{
  struct pcap_pkthdr *pkthdr;
  // data, packet 
  char *p1, *p2;
  value hdr, tval;

  va_start_void (alist);
  p1 = va_arg_ptr (alist, char *);

  pkthdr = va_arg_ptr (alist, struct pcap_pkthdr *);

  // ts.tv_sec, ts.tv_usec from pcap_pkthdr 
  tval = alloc_small (2, 0);
  Field (tval, 0) = Val_int (pkthdr->ts.tv_sec);
  Field (tval, 1) = Val_int (pkthdr->ts.tv_usec);

  // caplen, len from pcap_pkthdr 
  hdr = alloc_small (3, 0);
  Field (hdr, 0) = tval;
  Field (hdr, 1) = Val_int (pkthdr->caplen);
  Field (hdr, 2) = Val_int (pkthdr->len);

  // packet pointer 
  p2 = va_arg_ptr (alist, char *);

  callback3 (*(value *) cback, Val_bp (p1), hdr, Val_bp (p2));
  va_return_void (alist);
}


/* used for pcap_findalldevs() */
value
build_pcap_if_array (pcap_if * _c2)
{
  int cnt = 0;
  value _v1;
  value _v3[3];
  value _vres;
  pcap_if *dummy;

  _v3[0] = _v3[1] = _v3[2] = 0;

  /* count the entries in the linked list for latter camlidl_alloc() */
  dummy = _c2;
  while ((*dummy).next)
    {
      dummy = (*dummy).next;
      cnt++;
    }
  _vres = camlidl_alloc (cnt, 0);
  cnt = 0;

  Begin_roots_block (_v3, 3);
  while ((*_c2).next)
    {


      _v3[0] = copy_string ((*_c2).name);
      if ((*_c2).description == NULL || (*_c2).description == "") {
                _v3[1] = copy_string("No description");
          } else  _v3[1] = copy_string((*_c2).description);

          _v3[2] = Val_int((*_c2).flags);
          _v1 = camlidl_alloc_small(3, 0);
          Field(_v1, 0) = _v3[0];
          Field(_v1, 1) = _v3[1];
          Field(_v1, 2) = _v3[2];

          Field(_vres, cnt) = _v1;


         cnt++;
         _c2 = (*_c2).next;

 }

 End_roots();
 return _vres;

}

#ifdef HAVE_PCAP08

/* used for pcap_list_datalinks() */
value
build_pcap_int_array(int *_c2, int length) 
{
  int i;
  value _v1;
  value _vret;
  value _vres;

  _vret = 0;

  /* allocate array with length */
  _vres = camlidl_alloc(length, 0);

  Begin_roots1(_vret);

  for(i=0; i < length; i++) {
    /* actual field value */
    _vret = Val_int(_c2[i]);

    Field(_vres, i) = _vret;
  }

  End_roots();
  return _vres;
}

#endif

value camlidl_pcap_pcap_findalldevs(value _unit)
{
 pcap_if **alldevsp;
 int _res;
 pcap_if *_c1;
 value _vres;

 alldevsp = &_c1;
 {
 char errbuf[256];

  _res = pcap_findalldevs(alldevsp, errbuf);
  if(_res == -1)
        failwith(errbuf);
 }

 _vres = build_pcap_if_array(&**alldevsp);
 return _vres;

 }

#ifdef HAVE_PCAP08

value camlidl_pcap_pcap_list_datalinks(value _v_p) 
{
  int *dlt_buf,ret;
  pcap_handle p;
  value _v1;
  value _vresult;
  value _vres[2] = { 0, 0, };

  /* initialize pcap_handle p */
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  camlidl_ml2c_pcap_pcap_handle(_v_p, &p, _ctx);

  /* call the actual function and build the int array */
  ret = pcap_list_datalinks(p, &dlt_buf);
  _v1 = build_pcap_int_array(dlt_buf, ret);

  /* build the return values: int * int array */
  Begin_roots_block(_vres, 2)
    _vres[0] = Val_int(ret);
    _vres[1] = _v1;
    _vresult = camlidl_alloc_small(2, 0);
    Field(_vresult, 0) = _vres[0];
    Field(_vresult, 1) = _vres[1];
  End_roots()
  return _vresult;
}

#endif


