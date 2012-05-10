/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"@(#)__vexp.c	1.7	06/01/23 SMI"

/*
 * __vexp: double precision vector exp
 *
 * Algorithm:
 *
 * Write x = (k + j/256)ln2 + r, where k and j are integers, j >= 0,
 * and |r| <= ln2/512.  Then exp(x) = 2^k * 2^(j/256) * exp(r).
 * Compute exp(r) by a polynomial approximation exp(r) ~ 1 + p(r)
 * where p(r) := r*(1+r*(B1+r*(B2+r*B3))).  From a table, obtain
 * h and l such that h ~ 2^(j/256) to double precision and h+l
 * ~ 2^(j/256) to well more than double precision.  Then exp(x)
 * ~ 2^k * (h + (l + h * p(r))) to about double precision.  Note
 * that the multiplication by 2^k requires some finagling when
 * the result might be subnormal.
 *
 * Accuracy:
 *
 * For normal results, the largest error observed is less than
 * 0.6 ulps.  For subnormal results, the largest error observed
 * is 0.737 ulps.
 */

#include <sys/isa_defs.h>
#include "libm_macros.h"

static const double TBL[] = {
	1.00000000000000000000e+00,  0.00000000000000000000e+00,
	1.00271127505020252180e+00, -3.63661592869226394432e-17,
	1.00542990111280272636e+00,  9.49918653545503175702e-17,
	1.00815589811841754830e+00, -3.25205875608430806089e-17,
	1.01088928605170047526e+00, -1.52347786033685771763e-17,
	1.01363008495148942956e+00,  9.28359976818356758749e-18,
	1.01637831491095309566e+00, -5.77217007319966002766e-17,
	1.01913399607773791367e+00,  3.60190498225966110587e-17,
	1.02189714865411662714e+00,  5.10922502897344389359e-17,
	1.02466779289713572076e+00, -7.56160786848777820704e-17,
	1.02744594911876374610e+00, -4.95607417464536982418e-17,
	1.03023163768604097967e+00,  3.31983004108081294377e-17,
	1.03302487902122841490e+00,  7.60083887402708848935e-18,
	1.03582569360195719810e+00, -7.80678239133763616702e-17,
	1.03863410196137873065e+00,  5.99627378885251061843e-17,
	1.04145012468831610342e+00,  3.78483048028757620966e-17,
	1.04427378242741375480e+00,  8.55188970553796365958e-17,
	1.04710509587928979336e+00,  7.27707724310431474861e-17,
	1.04994408580068721015e+00,  5.59293784812700258637e-17,
	1.05279077300462642341e+00, -9.62948289902693573942e-17,
	1.05564517836055715705e+00,  1.75932573877209198414e-18,
	1.05850732279451276163e+00, -7.15265185663778073796e-17,
	1.06137722728926209292e+00, -1.19735370853656575649e-17,
	1.06425491288446449900e+00,  5.07875419861123039357e-17,
	1.06714040067682369717e+00, -7.89985396684158212226e-17,
	1.07003371182024187291e+00, -9.93716271128891938112e-17,
	1.07293486752597555522e+00, -3.83966884335882380671e-18,
	1.07584388906279104781e+00, -1.00027161511441361125e-17,
	1.07876079775711986031e+00, -6.65666043605659260344e-17,
	1.08168561499321524977e+00, -4.78262390299708626556e-17,
	1.08461836221330920615e+00,  3.16615284581634611576e-17,
	1.08755906091776965994e+00,  5.40934930782029075923e-18,
	1.09050773266525768967e+00, -3.04678207981247114697e-17,
	1.09346439907288583981e+00,  1.44139581472692093420e-17,
	1.09642908181637688259e+00, -5.91993348444931582405e-17,
	1.09940180263022191376e+00,  7.17045959970192322483e-17,
	1.10238258330784089090e+00,  5.26603687157069438656e-17,
	1.10537144570174117320e+00,  8.23928876050021358995e-17,
	1.10836841172367872588e+00, -8.78681384518052661558e-17,
	1.11137350334481754821e+00,  5.56394502666969764311e-17,
	1.11438674259589243221e+00,  1.04102784568455709549e-16,
	1.11740815156736927882e+00, -7.97680590262822045601e-17,
	1.12043775240960674644e+00, -6.20108590655417874998e-17,
	1.12347556733301989773e+00, -9.69973758898704299544e-17,
	1.12652161860824184814e+00,  5.16585675879545612073e-17,
	1.12957592856628807887e+00,  6.71280585872625658758e-17,
	1.13263851959871919561e+00,  3.23735616673800026374e-17,
	1.13570941415780546357e+00,  5.06659992612615524241e-17,
	1.13878863475669156458e+00,  8.91281267602540777782e-17,
	1.14187620396956157620e+00,  4.65109117753141238741e-17,
	1.14497214443180417298e+00,  4.64128989217001065651e-17,
	1.14807647884017893780e+00,  6.89774023662719177044e-17,
	1.15118922995298267331e+00,  3.25071021886382721198e-17,
	1.15431042059021593538e+00,  1.04171289462732661865e-16,
	1.15744007363375112085e+00, -9.12387123113440028710e-17,
	1.16057821202749877898e+00, -3.26104020541739310553e-17,
	1.16372485877757747552e+00,  3.82920483692409349872e-17,
	1.16688003695248165847e+00, -8.79187957999916974198e-17,
	1.17004376968325018993e+00, -1.84774420179000469438e-18,
	1.17321608016363732041e+00, -7.28756258658499447915e-17,
	1.17639699165028122074e+00,  5.55420325421807896277e-17,
	1.17958652746287584456e+00,  1.00923127751003904354e-16,
	1.18278471098434101449e+00,  1.54297543007907605845e-17,
	1.18599156566099384058e+00, -9.20950683529310590495e-18,
	1.18920711500272102690e+00,  3.98201523146564611098e-17,
	1.19243138258315117817e+00,  4.39755141560972082715e-17,
	1.19566439203982732842e+00,  4.61660367048148139743e-17,
	1.19890616707438057986e+00, -9.80919335600842311848e-17,
	1.20215673145270307565e+00,  6.64498149925230124489e-17,
	1.20541610900512385918e+00, -3.35727219326752963448e-17,
	1.20868432362658162482e+00, -4.74672594522898409739e-17,
	1.21196139927680124337e+00, -4.89061107752111835732e-17,
	1.21524735998046895524e+00, -7.71263069268148813091e-17,
	1.21854222982740845183e+00, -9.00672695836383767487e-17,
	1.22184603297275762301e+00, -1.06110212114026911612e-16,
	1.22515879363714552674e+00, -8.90353381426998342947e-17,
	1.22848053610687002468e+00, -1.89878163130252995312e-17,
	1.23181128473407586199e+00,  7.38938247161005024655e-17,
	1.23515106393693341325e+00, -1.07552443443078413783e-16,
	1.23849989819981654016e+00,  2.76770205557396742995e-17,
	1.24185781207348400201e+00,  4.65802759183693679123e-17,
	1.24522483017525797955e+00, -4.67724044984672750044e-17,
	1.24860097718920481924e+00, -8.26181099902196355046e-17,
	1.25198627786631622172e+00,  4.83416715246989759959e-17,
	1.25538075702469109629e+00, -6.71138982129687841853e-18,
	1.25878443954971652730e+00, -8.42178258773059935677e-17,
	1.26219735039425073886e+00, -3.08446488747384584900e-17,
	1.26561951457880628169e+00,  4.25057700345086802072e-17,
	1.26905095719173321989e+00,  2.66793213134218609523e-18,
	1.27249170338940276181e+00, -1.05779162672124210291e-17,
	1.27594177839639200123e+00,  9.91543024421429032951e-17,
	1.27940120750566932450e+00, -9.75909500835606221035e-17,
	1.28287001607877826359e+00,  1.71359491824356096814e-17,
	1.28634822954602556777e+00, -3.41695570693618197638e-17,
	1.28983587340666572274e+00,  8.94925753089759172195e-17,
	1.29333297322908946647e+00, -2.97459044313275164581e-17,
	1.29683955465100964055e+00,  2.53825027948883149593e-17,
	1.30035564337965059423e+00,  5.67872810280221742200e-17,
	1.30388126519193581210e+00,  8.64767559826787117946e-17,
	1.30741644593467731816e+00, -7.33664565287886889230e-17,
	1.31096121152476441374e+00, -7.18153613551945385697e-17,
	1.31451558794935463581e+00,  2.26754331510458564505e-17,
	1.31807960126606404927e+00, -5.45795582714915288619e-17,
	1.32165327760315753913e+00, -2.48063824591302174150e-17,
	1.32523664315974132322e+00, -2.85873121003886075697e-17,
	1.32882972420595435459e+00,  4.08908622391016005195e-17,
	1.33243254708316150037e+00, -5.10158663091674334319e-17,
	1.33604513820414583236e+00, -5.89186635638880135250e-17,
	1.33966752405330291609e+00,  8.92728259483173198426e-17,
	1.34329973118683532185e+00, -5.80258089020143775130e-17,
	1.34694178623294580355e+00,  3.22406510125467916913e-17,
	1.35059371589203447428e+00, -8.28711038146241653260e-17,
	1.35425554693689265129e+00,  7.70094837980298946162e-17,
	1.35792730621290114179e+00, -9.52963574482518886709e-17,
	1.36160902063822475405e+00,  1.53378766127066804593e-18,
	1.36530071720401191548e+00, -1.00053631259747639350e-16,
	1.36900242297459051599e+00,  9.59379791911884877256e-17,
	1.37271416508766841424e+00, -4.49596059523484126201e-17,
	1.37643597075453016920e+00, -6.89858893587180104162e-17,
	1.38016786726023799048e+00,  1.05103145799699839462e-16,
	1.38390988196383202258e+00, -6.77051165879478628716e-17,
	1.38766204229852907481e+00,  8.42298427487541531762e-17,
	1.39142437577192623621e+00, -4.90617486528898870821e-17,
	1.39519690996620027157e+00, -9.32933622422549531960e-17,
	1.39897967253831123635e+00, -9.61421320905132307233e-17,
	1.40277269122020475933e+00, -5.29578324940798922316e-17,
	1.40657599381901543545e+00,  7.03491481213642218800e-18,
	1.41038960821727066275e+00,  4.16654872843506164270e-17,
	1.41421356237309514547e+00, -9.66729331345291345105e-17,
	1.41804788432041517510e+00,  2.27443854218552945230e-17,
	1.42189260216916557589e+00, -1.60778289158902441338e-17,
	1.42574774410549420800e+00,  9.88069075850060728430e-17,
	1.42961333839197002327e+00, -1.20316424890536551792e-17,
	1.43348941336778890054e+00, -5.80245424392682610310e-17,
	1.43737599744898236764e+00, -4.20403401646755661225e-17,
	1.44127311912862565713e+00,  5.60250365087898567501e-18,
	1.44518080697704665027e+00, -3.02375813499398731940e-17,
	1.44909908964203504311e+00, -6.25940500081930925441e-17,
	1.45302799584905262265e+00, -5.77994860939610610226e-17,
	1.45696755440144376514e+00,  5.64867945387699814049e-17,
	1.46091779418064704466e+00, -5.60037718607521580013e-17,
	1.46487874414640573129e+00,  9.53076754358715731900e-17,
	1.46885043333698184220e+00,  8.46588275653362637570e-17,
	1.47283289086936752810e+00,  6.69177408194058937165e-17,
	1.47682614593949934623e+00, -3.48399455689279579579e-17,
	1.48083022782247186733e+00, -9.68695210263061857841e-17,
	1.48484516587275239274e+00,  1.07800867644074807559e-16,
	1.48887098952439700383e+00,  6.15536715774287133031e-17,
	1.49290772829126483501e+00,  1.41929201542840357707e-17,
	1.49695541176723545540e+00, -2.86166325389915821109e-17,
	1.50101406962642558440e+00, -6.41376727579023503859e-17,
	1.50508373162340647333e+00,  7.07471061358284636429e-17,
	1.50916442759342284141e+00, -1.01645532775429503911e-16,
	1.51325618745260981335e+00,  8.88449785133871209093e-17,
	1.51735904119821474190e+00, -4.30869947204334080070e-17,
	1.52147301890881458952e+00, -5.99638767594568341985e-18,
	1.52559815074453819506e+00,  1.11795187801605698722e-16,
	1.52973446694728698603e+00,  3.78579211515721903683e-17,
	1.53388199784095591305e+00,  8.87522684443844614135e-17,
	1.53804077383165682669e+00,  1.01746723511613580618e-16,
	1.54221082540794074411e+00,  7.94983480969762085616e-17,
	1.54639218314102144802e+00,  1.06839600056572198028e-16,
	1.55058487768499997372e+00, -1.46007065906893851791e-17,
	1.55478893977708865215e+00, -8.00316135011603564104e-17,
	1.55900440023783692922e+00,  3.78120705335752750188e-17,
	1.56323128997135762930e+00,  7.48477764559073438896e-17,
	1.56746963996555299659e+00, -1.03520617688497219883e-16,
	1.57171948129234140268e+00, -3.34298400468720006928e-17,
	1.57598084510788649659e+00, -1.01369164712783039808e-17,
	1.58025376265282457844e+00, -5.16340292955446806159e-17,
	1.58453826525249374946e+00, -1.93377170345857029304e-17,
	1.58883438431716395023e+00, -5.99495011882447940052e-18,
	1.59314215134226699888e+00, -1.00944065423119624890e-16,
	1.59746159790862707339e+00,  2.48683927962209992069e-17,
	1.60179275568269341434e+00, -6.05491745352778434252e-17,
	1.60613565641677102924e+00, -1.03545452880599952591e-16,
	1.61049033194925428347e+00,  2.47071925697978878522e-17,
	1.61485681420486071325e+00, -7.31666339912512326264e-17,
	1.61923513519486372836e+00,  2.09413341542290924068e-17,
	1.62362532701732886764e+00, -3.58451285141447470996e-17,
	1.62802742185734783398e+00, -6.71295508470708408630e-17,
	1.63244145198727497181e+00,  9.85281923042999296414e-17,
	1.63686744976696441078e+00,  7.69832507131987557450e-17,
	1.64130544764400632118e+00, -9.24756873764070550805e-17,
	1.64575547815396494578e+00, -1.01256799136747726038e-16,
	1.65021757392061774183e+00,  9.13327958872990419009e-18,
	1.65469176765619430114e+00,  9.64329430319602742879e-17,
	1.65917809216161615815e+00, -7.27554555082304942180e-17,
	1.66367658032673637614e+00,  5.89099269671309967045e-17,
	1.66818726513058246397e+00,  4.26917801957061447430e-17,
	1.67271017964159662839e+00, -5.47671596459956307616e-17,
	1.67724535701787846875e+00,  8.30394950995073155275e-17,
	1.68179283050742900407e+00,  8.19901002058149652013e-17,
	1.68635263344839336774e+00, -7.18146327835800944212e-17,
	1.69092479926930527867e+00, -9.66967147439488016590e-17,
	1.69550936148933262260e+00,  7.23841687284516664081e-17,
	1.70010635371852347753e+00, -8.02371937039770024589e-18,
	1.70471580965805125096e+00, -2.72888328479728156257e-17,
	1.70933776310046292579e+00, -9.86877945663293107628e-17,
	1.71397224792992597386e+00,  6.47397510775336706412e-17,
	1.71861929812247793414e+00, -1.85138041826311098821e-17,
	1.72327894774627399244e+00, -9.52212380039379996275e-17,
	1.72795123096183766975e+00, -1.07509818612046424459e-16,
	1.73263618202231106658e+00, -1.69805107431541549407e-18,
	1.73733383527370621735e+00,  3.16438929929295694659e-17,
	1.74204422515515644498e+00, -1.52595911895078879236e-18,
	1.74676738619916904760e+00, -1.07522904835075145042e-16,
	1.75150335303187820735e+00, -5.12445042059672465939e-17,
	1.75625216037329945351e+00,  2.96014069544887330703e-17,
	1.76101384303758390359e+00, -7.94325312503922771057e-17,
	1.76578843593327272643e+00,  9.46131501808326786660e-17,
	1.77057597406355471392e+00,  5.96179451004055584767e-17,
	1.77537649252652118825e+00,  6.42973179655657203396e-17,
	1.78019002651542446181e+00, -5.28462728909161736517e-17,
	1.78501661131893496481e+00,  1.53304001210313138184e-17,
	1.78985628232140103755e+00, -4.15435466068334977098e-17,
	1.79470907500310716820e+00,  1.82274584279120867698e-17,
	1.79957502494053511732e+00, -2.52688923335889795224e-17,
	1.80445416780662393208e+00, -5.17722240879331788328e-17,
	1.80934653937103195886e+00, -9.03264140245002968190e-17,
	1.81425217550039885595e+00, -9.96953153892034881983e-17,
	1.81917111215860849427e+00,  7.40267690114583888997e-17,
	1.82410338540705341259e+00, -1.01596278622770830650e-16,
	1.82904903140489727420e+00,  6.88919290883569563697e-17,
	1.83400808640934243066e+00,  3.28310722424562658722e-17,
	1.83898058677589371079e+00,  6.91896974027251194233e-18,
	1.84396656895862598446e+00, -5.93974202694996455028e-17,
	1.84896606951045083811e+00,  9.02758044626108928816e-17,
	1.85397912508338547077e+00,  9.76188749072759353840e-17,
	1.85900577242882047990e+00, -9.52870546198994068663e-17,
	1.86404604839778897940e+00,  6.54091268062057047791e-17,
	1.86909998994123860427e+00, -9.93850521425506708290e-17,
	1.87416763411029996256e+00, -6.12276341300414256164e-17,
	1.87924901805656019427e+00, -1.62263155578358447799e-17,
	1.88434417903233453195e+00, -8.22659312553371090551e-17,
	1.88945315439093919352e+00, -9.00516828505912548531e-17,
	1.89457598158696560731e+00,  3.40340353521652967060e-17,
	1.89971269817655530332e+00, -3.85973976937851370678e-17,
	1.90486334181767413831e+00,  6.53385751471827862895e-17,
	1.91002795027038985154e+00, -5.90968800674406023686e-17,
	1.91520656139714740007e+00, -1.06199460561959626376e-16,
	1.92039921316304740273e+00,  7.11668154063031418621e-17,
	1.92560594363612502811e+00, -9.91496376969374092749e-17,
	1.93082679098762710623e+00,  6.16714970616910955284e-17,
	1.93606179349229434727e+00,  1.03323859606763257448e-16,
	1.94131098952864045160e+00, -6.63802989162148798984e-17,
	1.94657441757923321823e+00,  6.81102234953387718436e-17,
	1.95185211623097831790e+00, -2.19901696997935108603e-17,
	1.95714412417540017941e+00,  8.96076779103666776760e-17,
	1.96245048020892731699e+00,  1.09768440009135469493e-16,
	1.96777122323317588126e+00, -1.03149280115311315109e-16,
	1.97310639225523432039e+00, -7.45161786395603748608e-18,
	1.97845602638795092787e+00,  4.03887531092781665750e-17,
	1.98382016485021939189e+00, -2.20345441239106265716e-17,
	1.98919884696726634310e+00,  8.20513263836919941553e-18,
	1.99459211217094023461e+00,  1.79097103520026450854e-17
};

static const union {
	unsigned	i[2];
	double		d;
} C[] = {
	{ DBLWORD(0x43380000, 0x00000000) },
	{ DBLWORD(0x40771547, 0x652b82fe) },
	{ DBLWORD(0x3f662e42, 0xfee00000) },
	{ DBLWORD(0x3d6a39ef, 0x35793c76) },
	{ DBLWORD(0x3ff00000, 0x00000000) },
	{ DBLWORD(0x3fdfffff, 0xfffffff6) },
	{ DBLWORD(0x3fc55555, 0x721a1d14) },
	{ DBLWORD(0x3fa55555, 0x6e0896af) },
	{ DBLWORD(0x01000000, 0x00000000) },
	{ DBLWORD(0x7f000000, 0x00000000) },
	{ DBLWORD(0x40862e42, 0xfefa39ef) },
	{ DBLWORD(0xc0874910, 0xd52d3051) },
	{ DBLWORD(0xfff00000, 0x00000000) },
	{ DBLWORD(0x00000000, 0x00000000) }
};

#define	round		C[0].d
#define	invln2_256	C[1].d
#define	ln2_256h	C[2].d
#define	ln2_256l	C[3].d
#define	one		C[4].d
#define	B1		C[5].d
#define	B2		C[6].d
#define	B3		C[7].d
#define	tiny		C[8].d
#define	huge		C[9].d
#define	othresh		C[10].d
#define	uthresh		C[11].d
#define	neginf		C[12].d
#define	zero		C[13].d

#define	PROCESS(N)						\
	y##N = (x##N * invln2_256) + round;			\
	j##N = LO(y##N);					\
	y##N -= round;						\
	k##N = j##N >> 8;					\
	j##N = (j##N & 0xff) << 1;				\
	x##N = (x##N - y##N * ln2_256h) - y##N * ln2_256l;	\
	y##N = x##N * (one + x##N * (B1 + x##N * (B2 + x##N * B3)));	\
	t##N = TBL[j##N];					\
	y##N = t##N + (TBL[j##N + 1] + t##N * y##N);		\
	if (k##N < -1021) {					\
		HI(y##N) += (k##N + 0x3ef) << 20;		\
		y##N *= tiny;					\
	} else {						\
		HI(y##N) += k##N << 20;				\
	}							\
	*y = y##N;						\
	y += stridey

#define	PREPROCESS(N, index, label)				\
	hx = HI(x[0]);						\
	ix = hx & ~0x80000000;					\
	x##N = *x;						\
	x += stridex;						\
	if (ix >= 0x40862e42) {					\
		if (ix >= 0x7ff00000) { /* x is inf or nan */	\
			y[index] = (x##N == neginf)? zero :	\
			    x##N * x##N;			\
			goto label;				\
		}						\
		if (x##N > othresh) {				\
			y[index] = huge * huge;			\
			goto label;				\
		}						\
		if (x##N < uthresh) {				\
			y[index] = tiny * tiny;			\
			goto label;				\
		}						\
	} else if (ix < 0x3e300000) { /* |x| < 2^-28 */		\
		y[index] = one + x##N;				\
		goto label;					\
	}

void
__vexp(int n, double *restrict x, int stridex, double *restrict y,
    int stridey)
{
	double		x0, x1, x2, x3, x4, x5;
	double		y0, y1, y2, y3, y4, y5;
	double		t0, t1, t2, t3, t4, t5;
	int		k0, k1, k2, k3, k4, k5;
	int		j0, j1, j2, j3, j4, j5;
	int		hx, ix;

	y -= stridey;

	for (;;) {
begin:
		if (--n < 0)
			break;
		y += stridey;

		PREPROCESS(0, 0, begin);

		if (--n < 0)
			goto process1;

		PREPROCESS(1, stridey, process1);

		if (--n < 0)
			goto process2;

		PREPROCESS(2, stridey << 1, process2);

		if (--n < 0)
			goto process3;

		PREPROCESS(3, (stridey << 1) + stridey, process3);

		if (--n < 0)
			goto process4;

		PREPROCESS(4, stridey << 2, process4);

		if (--n < 0)
			goto process5;

		PREPROCESS(5, (stridey << 2) + stridey, process5);

		y0 = (x0 * invln2_256) + round;
		y1 = (x1 * invln2_256) + round;
		y2 = (x2 * invln2_256) + round;
		y3 = (x3 * invln2_256) + round;
		y4 = (x4 * invln2_256) + round;
		y5 = (x5 * invln2_256) + round;

		j0 = LO(y0);
		j1 = LO(y1);
		j2 = LO(y2);
		j3 = LO(y3);
		j4 = LO(y4);
		j5 = LO(y5);

		y0 -= round;
		y1 -= round;
		y2 -= round;
		y3 -= round;
		y4 -= round;
		y5 -= round;

		k0 = j0 >> 8;
		k1 = j1 >> 8;
		k2 = j2 >> 8;
		k3 = j3 >> 8;
		k4 = j4 >> 8;
		k5 = j5 >> 8;

		j0 = (j0 & 0xff) << 1;
		j1 = (j1 & 0xff) << 1;
		j2 = (j2 & 0xff) << 1;
		j3 = (j3 & 0xff) << 1;
		j4 = (j4 & 0xff) << 1;
		j5 = (j5 & 0xff) << 1;

		x0 = (x0 - y0 * ln2_256h) - y0 * ln2_256l;
		x1 = (x1 - y1 * ln2_256h) - y1 * ln2_256l;
		x2 = (x2 - y2 * ln2_256h) - y2 * ln2_256l;
		x3 = (x3 - y3 * ln2_256h) - y3 * ln2_256l;
		x4 = (x4 - y4 * ln2_256h) - y4 * ln2_256l;
		x5 = (x5 - y5 * ln2_256h) - y5 * ln2_256l;

		y0 = x0 * (one + x0 * (B1 + x0 * (B2 + x0 * B3)));
		y1 = x1 * (one + x1 * (B1 + x1 * (B2 + x1 * B3)));
		y2 = x2 * (one + x2 * (B1 + x2 * (B2 + x2 * B3)));
		y3 = x3 * (one + x3 * (B1 + x3 * (B2 + x3 * B3)));
		y4 = x4 * (one + x4 * (B1 + x4 * (B2 + x4 * B3)));
		y5 = x5 * (one + x5 * (B1 + x5 * (B2 + x5 * B3)));

		t0 = TBL[j0];
		t1 = TBL[j1];
		t2 = TBL[j2];
		t3 = TBL[j3];
		t4 = TBL[j4];
		t5 = TBL[j5];

		y0 = t0 + (TBL[j0 + 1] + t0 * y0);
		y1 = t1 + (TBL[j1 + 1] + t1 * y1);
		y2 = t2 + (TBL[j2 + 1] + t2 * y2);
		y3 = t3 + (TBL[j3 + 1] + t3 * y3);
		y4 = t4 + (TBL[j4 + 1] + t4 * y4);
		y5 = t5 + (TBL[j5 + 1] + t5 * y5);

		if (k0 < -1021) {
			HI(y0) += (k0 + 0x3ef) << 20;
			y0 *= tiny;
		} else {
			HI(y0) += k0 << 20;
		}
		if (k1 < -1021) {
			HI(y1) += (k1 + 0x3ef) << 20;
			y1 *= tiny;
		} else {
			HI(y1) += k1 << 20;
		}
		if (k2 < -1021) {
			HI(y2) += (k2 + 0x3ef) << 20;
			y2 *= tiny;
		} else {
			HI(y2) += k2 << 20;
		}
		if (k3 < -1021) {
			HI(y3) += (k3 + 0x3ef) << 20;
			y3 *= tiny;
		} else {
			HI(y3) += k3 << 20;
		}
		if (k4 < -1021) {
			HI(y4) += (k4 + 0x3ef) << 20;
			y4 *= tiny;
		} else {
			HI(y4) += k4 << 20;
		}
		if (k5 < -1021) {
			HI(y5) += (k5 + 0x3ef) << 20;
			y5 *= tiny;
		} else {
			HI(y5) += k5 << 20;
		}

		y[0] = y0;
		y[stridey] = y1;
		y[stridey << 1] = y2;
		y[(stridey << 1) + stridey] = y3;
		y[stridey << 2] = y4;
		y[(stridey << 2) + stridey] = y5;
		y += (stridey << 2) + stridey;
		continue;

process1:
		PROCESS(0);
		continue;

process2:
		PROCESS(0);
		PROCESS(1);
		continue;

process3:
		PROCESS(0);
		PROCESS(1);
		PROCESS(2);
		continue;

process4:
		PROCESS(0);
		PROCESS(1);
		PROCESS(2);
		PROCESS(3);
		continue;

process5:
		PROCESS(0);
		PROCESS(1);
		PROCESS(2);
		PROCESS(3);
		PROCESS(4);
	}
}
