package main

import (
	"encoding/json"
	"log"
	"math"

	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/drlwe"
)

func main() {

	n := 10
	t := 10

	ckksParams, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 14,
		LogQ: []int{52, 47, 47, 47, 47, 47, 47},
		LogP: []int{52, 52},
	})
	if err != nil {
		panic(err)
	}

	var rots []int
	err = json.Unmarshal([]byte("[7645,7612,719,256,7544,774,7552,7491,7477,526,540,7652,581,7605,726,7440,643,7476,800,8128,523,7628,631,612,662,733,744,7559,517,7643,580,7611,626,7450,27,7629,7625,661,7507,568,7600,638,674,751,7558,7468,742,7448,576,572,586,7562,693,7433,745,7442,7674,600,601,7573,7545,513,7449,763,7413,7656,7533,7510,708,760,7615,7599,7587,689,7455,585,633,713,7479,7655,538,557,23,31,512,8184,7671,564,567,583,660,7511,352,416,7673,7627,7620,7454,739,753,7438,7425,10,561,562,602,616,556,7583,7516,5840,622,7475,7647,7597,639,1,11,384,680,8064,527,7574,7420,762,29,7581,675,683,7484,22,7563,755,7421,7412,32,8189,715,725,570,617,7517,7509,7546,7534,7493,554,566,569,606,609,7569,754,764,519,539,560,596,657,7515,7514,128,520,7666,7604,664,6,30,7646,7490,7414,768,531,7658,7621,7470,544,1136,7670,584,695,8188,7648,7585,7566,677,17,224,516,7675,7630,545,7474,721,736,7641,625,7461,26,448,7677,7660,7536,7595,668,7483,7936,8186,541,577,590,7446,547,603,653,676,692,7409,7,19,7602,710,759,8183,7508,7637,7519,7541,7526,7512,7669,592,593,7589,647,709,7417,7636,7584,734,7436,8191,7624,7577,7465,2704,607,7496,711,748,64,7650,573,648,652,7487,714,7588,7564,7555,684,696,7452,773,608,542,594,7543,7538,7613,7619,7575,7540,682,7431,673,12,7623,7525,7495,7488,7622,747,7423,24,7408,7481,738,7443,7616,697,776,559,629,705,7445,14,7639,7635,7570,627,7523,750,928,7661,551,591,641,7530,7638,7632,7609,599,651,529,7548,7537,7535,7497,7424,160,8187,532,575,7430,7680,7610,588,649,7539,13,628,666,749,549,699,7459,7437,611,614,7578,640,536,7644,7642,563,644,555,7618,7614,589,7551,730,767,769,992,571,7591,7501,525,605,7567,717,7601,735,746,7444,7653,7554,598,7572,8176,515,7665,7634,579,731,781,320,704,8185,7664,7561,96,663,701,780,670,8,7606,7603,7592,654,783,3,7598,619,679,7478,7460,7679,7531,7527,7506,7463,779,7649,7576,7550,650,7435,7565,7447,9,7633,7596,604,624,690,728,546,7631,7608,620,665,1568,524,646,7528,621,7560,634,716,7415,7659,565,7607,669,630,7557,7502,775,480,7582,613,729,5056,7471,1920,7663,7489,737,28,7626,7593,7434,528,578,595,7472,722,723,7469,7411,25,672,7532,7529,718,16,7657,703,720,766,574,635,7482,782,5,658,7429,757,610,667,691,694,741,587,656,552,681,7441,3136,7672,7651,778,896,7668,632,7451,752,758,770,7556,7513,706,7485,7480,7418,548,7547,7522,7505,7432,8190,7518,960,553,582,7590,7586,2,784,7549,7542,550,7571,636,698,618,623,659,671,771,7419,4,7640,688,7498,756,7464,15,864,537,7503,7492,685,288,8160,700,732,521,7667,7520,18,192,6624,3488,514,712,7422,645,686,7499,7439,7426,727,7456,535,7579,7524,707,7473,4272,530,534,687,777,7654,558,7580,615,543,637,642,655,7678,7662,7428,518,7410,597,7521,7457,740,7416,7427,7676,533,7594,678,7466,7462,772,7568,7494,7486,724,7467,761,765,21,832,702,7458,743,7500,7453,20,522,7617,7553,7504]"), &rots)
	if err != nil {
		panic(err)
	}

	//params := bootstrapping.N15QP768H192H32
	// ckksParamsLit, btpParams, err := bootstrapping.NewParametersFromLiteral(params.SchemeParams, params.BootstrappingParams)
	// if err != nil {
	// 	panic(err)
	// }
	// ckksParams, err := ckks.NewParametersFromLiteral(ckksParamsLit)
	// if err != nil {
	// 	panic(err)
	// }

	galEls := ckksParams.GaloisElements(rots)

	// setupJson, err := json.Marshal(setup.Description{
	// 	GaloisEls: galEls,
	// })
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println(string(setupJson))

	share := drlwe.NewGaloisKeyGenProtocol(ckksParams.Parameters).AllocateShare()

	shareb, err := share.MarshalBinary()
	if err != nil {
		panic(err)
	}

	shareSize := len(shareb)

	nprotos := len(galEls)

	nparticip := int(math.Ceil(float64(nprotos) * (float64(t) / float64(n))))

	log.Printf("Share size: %s\n", utils.ByteCountSI(uint64(shareSize)))

	log.Printf("Cloud based (party): Total for party: %d particip, sent: %s\n", nparticip, utils.ByteCountSI(uint64(nparticip*shareSize)))

	naggreg := len(galEls) / n

	nsimple := nparticip - naggreg

	totSent := nsimple*shareSize + naggreg*(n-1)*shareSize

	totRecv := naggreg*(t-1)*shareSize + (nprotos-naggreg)*shareSize

	log.Printf("Aggreg: Total for party: %d particip, %d aggreg, %d simp, sent: %s recv: %s \n", nparticip, naggreg, nsimple, utils.ByteCountSI(uint64(totSent)), utils.ByteCountSI(uint64(totRecv)))

	totSentBrdc := nparticip * (n - 1) * shareSize

	npassive := nprotos - nparticip

	totRecvBrdc := (nparticip*(t-1) + (npassive * t)) * shareSize

	log.Printf("Broadcast: Total for party: %d particip, %d passive, sent: %s recv: %s \n", nparticip, npassive, utils.ByteCountSI(uint64(totSentBrdc)), utils.ByteCountSI(uint64(totRecvBrdc)))
}
