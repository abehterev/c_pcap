/***************************************************************************
 *  libdisorder: A Library for Measuring Byte Stream Entropy
 *  Copyright (C) 2010 Michael E. Locasto
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the:
 *       Free Software Foundation, Inc.
 *       59 Temple Place, Suite 330
 *       Boston, MA  02111-1307  USA
 *
 * $Id$
 **************************************************************************/

#include <math.h> //for log2()
#include <stdio.h> //for NULL
#include "disorder.h"

/** Frequecies for each byte */
static int m_token_freqs[LIBDO_MAX_BYTES]; //frequency of each token in sample
static int m_num_tokens = 0; //actual number of `seen' tokens, max 256 
static double m_maxent = 0.0;
static double m_ratio = 0.0;
static int LIBDISORDER_INITIALIZED = 0;

static void
initialize_lib()
{
  m_num_tokens = 0;

  int i = 0;
  for(i=0;i<LIBDO_MAX_BYTES;i++)
  {
    m_token_freqs[i]=0;
  }
}

/**
 * Set m_num_tokens by iterating over m_token_freq[] and maintaining
 * a counter of each position that does not hold the value of zero.
 */
static void
count_num_tokens()
{
  int i = 0;
  int counter = 0;
  for(i=0;i<LIBDO_MAX_BYTES;i++)
  {
    if(0!=m_token_freqs[i])
    {
      counter++;
    }
  }
  m_num_tokens = counter;
}

/**
 * Sum frequencies for each token (i.e., byte values 0 through 255)
 * We assume the `length' parameter is correct.
 *
 * This function is available only to functions in this file.
 */
static void
get_token_frequencies(const char* buf, 
		      unsigned long length)
{
  unsigned long i=0;
  for(i=0;i<length;i++)
  {
    unsigned char c = (unsigned char)*buf ++;
    m_token_freqs[c]++;
  }
}

/**
 * Return entropy (in bits) of this buffer of bytes. We assume that the
 * `length' parameter is correct. This implementation is a translation
 * of the PHP code found here:
 *
 *    http://onlamp.com/pub/a/php/2005/01/06/entropy.html
 *
 * with a helpful hint on the `foreach' statement from here:
 *
 *    http://php.net/manual/en/control-structures.foreach.php
 */
double
shannon_H(const char* buf, 
	  unsigned long length)
{
  int i = 0;
  double bits = 0.0;
  unsigned long num_events = 0; //`length' parameter
  double freq = 0.0; //loop variable for holding freq from m_token_freq[]
  double entropy = 0.0; //running entropy sum

  if(NULL==buf || 0==length)
    return 0.0;

    initialize_lib();

  m_maxent = 0.0;
  m_ratio = 0.0;
  num_events = length;
  get_token_frequencies(buf, num_events); //modifies m_token_freqs[]
  //set m_num_tokens by counting unique m_token_freqs entries
  count_num_tokens(); 

  if(m_num_tokens>LIBDO_MAX_BYTES)
  {
    //report error somehow?
    return 0.0;
  }

  //iterate through whole m_token_freq array, but only count
  //spots that have a registered token (i.e., freq>0)
  for(i=0;i<LIBDO_MAX_BYTES;i++)
  {
    if(0!=m_token_freqs[i])
    {
      freq = ((double)m_token_freqs[ i ]); 
      double prob = (freq / ((double)num_events));
      entropy += prob * log2( prob );
    }
  }

  bits = -1.0 * entropy;
  m_maxent = log2(m_num_tokens);
  m_ratio = bits / m_maxent;

  return bits;
}

int 
get_num_tokens()
{
  return m_num_tokens;
}

double 
get_max_entropy()
{
  return m_maxent;
}

double 
get_entropy_ratio()
{
  return m_ratio;
}
